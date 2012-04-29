/*
 * A demo VFS module
 *
 * Copyright (C) Richard Sharpe, 2012
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the 
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distrubuted in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>

#include "includes.h"
#include "smbd/smbd.h"
#include <fcntl.h>
#include <semaphore.h>
#include <syslog.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define DEMO_MODULE_NAME "vfs_demo"
#define LOG_QUEUE_SIZE 10

struct demo_struct {
	const char *audit_path;
	uint32 match_count;
	pthread_t log_thread;     /* The thread that logs things to syslog */
	/* A simple queue of logging requests */
	sem_t send_sem, recv_sem;
	struct cmd_struct *log_cmd_queue[LOG_QUEUE_SIZE];
	unsigned int send_index;
	unsigned int recv_index;
	int res;
};

enum cmd_enum { LOG_EXIT = 0, LOG_LOG };

struct cmd_struct {
	struct demo_struct *ctx;
	const char *file_path;
	enum cmd_enum cmd;
};

static bool send_cmd(struct cmd_struct *cmd)
{
	int res = 0;

	/*
	 * Is there space? If not we wait 
	 */
	res = sem_wait(&cmd->ctx->send_sem);
	if (res < 0) {
		DEBUG(1, ("Failed to wait on the send semaphore: %s\n",
			strerror(errno)));
		return false;
	}

	cmd->ctx->log_cmd_queue[cmd->ctx->send_index] = cmd;
	cmd->ctx->send_index++;
	if (cmd->ctx->send_index >= LOG_QUEUE_SIZE)
		cmd->ctx->send_index = 0;

	/*
	 * Tell the write thread that it has something to do
	 */
	res = sem_post(&cmd->ctx->recv_sem);
	if (res < 0) {
		DEBUG(1, ("Failed to send on the recv semaphore: %s\n",
			strerror(errno)));
		return false;
	}

	DEBUG(10, ("Command %p sent ...\n", cmd));

	return true;
}

/*
 * Create a command to send to the logging thread. Copy the passed in file name
 * into the command etc. Use the context as a talloc context. The command will
 * be free'd by the logging thread.
 */
static struct cmd_struct *create_cmd(struct demo_struct *ctx,
				     enum cmd_enum cmd,
				     const char *file_path)
{
	struct cmd_struct *the_cmd;

	/* Make it a child of the context */
	the_cmd = talloc_zero(ctx, struct cmd_struct);
	if (!the_cmd) {
		DEBUG(1, ("Unable to allocate space for a logging command!\n"));
		return the_cmd;
	}

	the_cmd->ctx = ctx;
	the_cmd->cmd = cmd;
	if (file_path) {
		the_cmd->file_path = talloc_strdup(the_cmd, file_path);
		if (!the_cmd->file_path) {
			DEBUG(1, ("Unable to allocate space for file "
				"path: %s!\n",
				file_path));
			talloc_free(the_cmd);
			return NULL;
		}
	}

	return the_cmd;
}

/*
 * Logging thread ... we get an LOG_EXIT request when it is time to exit. That
 * will be the last request we get. We do a pthread_exit as the last thing.
 */
static void *logging_thread(void * param)
{
	struct demo_struct *ctx = (struct demo_struct *)param;
	int res = 0;
	struct cmd_struct *cmd = NULL;

	DEBUG(10, ("Logging thread starting with: %o\n", ctx));

	openlog("Samba Audit", LOG_NDELAY, LOG_DAEMON);

	/*
	 * Wait for a command.
	 */
	res = sem_wait(&ctx->recv_sem);
	while (!res || (errno != EINTR)) {
		/* What about EINTR? */

		cmd = ctx->log_cmd_queue[ctx->recv_index];
		DEBUG(10, ("cmd: %p, recv_index: %d\n", cmd, ctx->recv_index));
		ctx->recv_index++;
		if (ctx->recv_index >= LOG_QUEUE_SIZE)
			ctx->recv_index = 0;

		res = sem_post(&ctx->send_sem);

		DEBUG(10, ("Got a request for %s\n", 
			cmd->file_path ? cmd->file_path : ":none:"));

		switch (cmd->cmd) {
		case LOG_EXIT:
			talloc_free(cmd);  /* Since we are exiting the loop */
			goto done;
			break;

		case LOG_LOG:
			syslog(LOG_NOTICE, 
				"File %s accessed\n", 
				cmd->file_path);
			break;

		default:
			DEBUG(10, ("Unknown command\n"));	
			break;
		}

		talloc_free(cmd); /* We can get rid of this now */

		res = sem_wait(&ctx->recv_sem);
	}

	if (res < 0) {
		DEBUG(1, ("Failed to wait on the send semaphore: %s\n",
			strerror(errno)));
		return false;
	}

done:
	DEBUG(10, ("Logging thread terminating\n"));

	closelog();

	ctx->res = res;

	pthread_exit(&ctx->res); /* Let our creator know of errors */
}

/*
 * Handle a connection. We create our threads and then call the NEXT fn.
 */
static int demo_connect(vfs_handle_struct *handle,
			const char  *service,
			const char *user)
{
	int res = 0;
	struct demo_struct *ctx = NULL;

	/* 
	 * Allow the next module to handle connections first
	 * If we get an error, don't do any of our initialization.
	 */
	res = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (res) {
		return res;
	}

	/*
	 * Get some memory for the dir we are interested in watching and our
	 * other context info.
	 */
	ctx = talloc_zero(handle, struct demo_struct);
	if (!ctx) {
		DEBUG(0, ("Unable to allocate memory for our context, can't proceed!\n"));
		errno = ENOMEM;
		return -1;
	}

	ctx->audit_path = lp_parm_const_string(SNUM(handle->conn),
					       DEMO_MODULE_NAME,
					       "audit path",
					       NULL);

	DEBUG(10, ("audit path is \"%s\"", ctx->audit_path));

	res = sem_init(&ctx->send_sem, 0, LOG_QUEUE_SIZE);
	if (res) {
		DEBUG(1, ("Unable to initialize send sem: %s\n",
			strerror(errno)));
		goto error_no_thread;
	}

	res = sem_init(&ctx->recv_sem, 0, 0);
	if (res) {
		DEBUG(1, ("Unable to initialize recv sem: %s\n",
			strerror(errno)));
		goto error_no_thread;
	}

	res = pthread_create(&ctx->log_thread, 
			     NULL, 
			     logging_thread,
			     ctx);
	if (res) {
		DEBUG(1, ("Unable to create our background thread: %s\n",
			strerror(errno)));
		goto error_no_thread;
	} 

	SMB_VFS_HANDLE_SET_DATA(handle, ctx, NULL,
				struct demo_struct, goto error);

	return res;
error:

error_no_thread:
	talloc_free(ctx);
	return res;
}

/*
 * We need to clean up the thread we created on a disconnect as well as 
 * clean up memory.
 */
static void demo_disconnect(vfs_handle_struct *handle)
{
	int res = 0, *thread_res = NULL;
	struct demo_struct *ctx;
	struct cmd_struct *cmd;

	/* Let the next module do any cleanup it needs to */
	SMB_VFS_NEXT_DISCONNECT(handle);

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				goto ctx_error);

	/*
	 * Tell the background thread to exit
	 */
	cmd = create_cmd(ctx, LOG_EXIT, NULL);
	if (!cmd || !send_cmd(cmd)) {
		return;  /* Not much more to do here ... kill the thread? */
	}

	res = pthread_join(ctx->log_thread, (void **)&thread_res);
	if (res || *thread_res) {
		DEBUG(10, ("Error cleaning up thread: res: %s, "
			   "thread_res: %s\n",
			   strerror(errno), strerror(*thread_res)));
		return;
	}

	/*
	 * This is not absolutely needed since that structure used the handle
	 * as a talloc context ...*/
	talloc_free(ctx);

	return;
ctx_error:
	DEBUG(10, ("Error getting context for connection!\n"));
	return;
}

/*
 * Handle an opendir request. Check if the path that we are being asked to 
 * open has the audit path as a prefix. If so, send a message to the background
 * thread to have it send a message via syslog.
 */
static DIR *demo_opendir(vfs_handle_struct *handle,
			 const char *fname,
			 const char *mask,
			 uint32 attr)
{
	DIR *res;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				return NULL);

	if (ctx->audit_path && strstr(fname, ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, fname));

		cmd = create_cmd(ctx, LOG_LOG, fname);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	/* Allow the next module to handle the OPENDIR as we are done */
	res = SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	return res;
}

/*
 * Handle an FD-based opendir.
 */
static DIR *demo_fdopendir(vfs_handle_struct *handle,
			   files_struct *fsp,
			   const char *mask,
			   uint32 attr)
{
	DIR *res;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				return NULL);

	if (ctx->audit_path && strstr(fsp->fsp_name->base_name, 
				      ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, fsp->fsp_name->base_name));

		cmd = create_cmd(ctx, LOG_LOG, fsp->fsp_name->base_name);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	/* Allow the next module to handle the FOPENDIR as we are done */
	res = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
	return res;
}

/*
 * Handle a mkdir request.
 */
static int demo_mkdir(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	int res;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				errno = EACCES; return -1);

	if (ctx->audit_path && strstr(path, ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, path));

		cmd = create_cmd(ctx, LOG_LOG, path);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	res = SMB_VFS_NEXT_MKDIR(handle, path, mode);

	return res;
}

/*
 * Handle an rmdir request.
 */
static int demo_rmdir(vfs_handle_struct *handle, const char *path)
{
	int res;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				errno = EACCES; return -1);

	if (ctx->audit_path && strstr(path, ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, path));

		cmd = create_cmd(ctx, LOG_LOG, path);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	res = SMB_VFS_NEXT_RMDIR(handle, path);

	return res;
}

/*
 * Open a file and keep track of it ... in case it is changed.
 */
static int demo_open(vfs_handle_struct *handle,
		     struct smb_filename *smb_fname,
		     files_struct *fsp, 
		     int flags,
		     mode_t mode)
{
	int res = -1;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				return EACCES);

	if (ctx->audit_path && strstr(fsp->fsp_name->base_name, 
				      ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, fsp->fsp_name->base_name));

		cmd = create_cmd(ctx, LOG_LOG, smb_fname->base_name);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	/* Allow the next module to handle the OPEN as we are done */
	res = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

	return res;
}

/*
 * Handle a create_file request
 */
static NTSTATUS demo_create_file(vfs_handle_struct *handle,
				 struct smb_request *req,
				 uint16_t root_dir_fid,
				 struct smb_filename *smb_fname,
				 uint32_t access_mask,
				 uint32_t share_access,
				 uint32_t create_disposition,
				 uint32_t create_options,
				 uint32_t file_attributes,
				 uint32_t oplock_request,
				 uint64_t allocation_size,
				 uint32_t private_flags,
				 struct security_descriptor *sd,
				 struct ea_list *ea_list,
				 files_struct **result,
				 int *pinfo)
{
	NTSTATUS res;
	struct demo_struct *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, 
				ctx, 
				struct demo_struct,
				goto error);

	if (ctx->audit_path && strstr(smb_fname->base_name, 
				      ctx->audit_path)) {
		struct cmd_struct *cmd;
		DEBUG(10, ("Found %s in the path %s\n", 
			ctx->audit_path, smb_fname->base_name));

		cmd = create_cmd(ctx, LOG_LOG, smb_fname->base_name);
		if (!cmd || !send_cmd(cmd)) {
			DEBUG(1, ("Error logging. Continuing!\n"));
		}
	}

	/* Allow the next module to handle the CREATE_FILE as we are done */
	res = SMB_VFS_NEXT_CREATE_FILE(handle,
				       req,
				       root_dir_fid,
				       smb_fname,
				       access_mask,
				       share_access,
				       create_disposition,
				       create_options,
				       file_attributes,
				       oplock_request,
				       allocation_size,
				       private_flags,
				       sd,
				       ea_list,
				       result,
				       pinfo);

	return res;
error:
	DEBUG(0, ("Error retrieving context\n"));
	return NT_STATUS_ACCESS_DENIED;
}

static struct vfs_fn_pointers vfs_demo_fns = {
	.connect_fn = demo_connect,
	.disconnect_fn = demo_disconnect,

	.opendir_fn = demo_opendir,
	.fdopendir_fn = demo_fdopendir,
	.mkdir_fn = demo_mkdir,
	.rmdir_fn = demo_rmdir,

	.open_fn = demo_open,
	.create_file_fn = demo_create_file,
};

NTSTATUS vfs_demo_init(void);
NTSTATUS vfs_demo_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				DEMO_MODULE_NAME,
				&vfs_demo_fns);
}
