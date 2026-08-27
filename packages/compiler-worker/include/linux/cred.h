#pragma once
struct cred;
struct cred *prepare_kernel_cred(void *daemon);
int commit_creds(struct cred *new_cred);
void revert_creds(struct cred *old);
