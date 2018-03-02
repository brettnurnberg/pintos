#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define NUM_SYSCALL 13

static void syscall_handler (struct intr_frame *);
static void verify_address (const void *);
static struct file_descriptor* get_fd (int);

typedef uint32_t syscall_function (uint32_t *);
static syscall_function sys_halt;
static syscall_function sys_exit;
static syscall_function sys_exec;
static syscall_function sys_wait;
static syscall_function sys_create;
static syscall_function sys_remove;
static syscall_function sys_open;
static syscall_function sys_filesize;
static syscall_function sys_read;
static syscall_function sys_write;
static syscall_function sys_seek;
static syscall_function sys_tell;
static syscall_function sys_close;

static struct lock fs_lock;

/* Initializes system call functionality */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

/* Handles all system calls */
static void
syscall_handler (struct intr_frame *f) 
{
  /* A system call. */
  struct syscall
    {
      size_t arg_cnt;           /* Number of arguments. */
      syscall_function *func;   /* Implementation. */
    };

  /* Table of system calls. */
  static const struct syscall syscall_table[NUM_SYSCALL] =
    {
      {0, (syscall_function *) sys_halt},
      {1, (syscall_function *) sys_exit},
      {1, (syscall_function *) sys_exec},
      {1, (syscall_function *) sys_wait},
      {2, (syscall_function *) sys_create},
      {1, (syscall_function *) sys_remove},
      {1, (syscall_function *) sys_open},
      {1, (syscall_function *) sys_filesize},
      {3, (syscall_function *) sys_read},
      {3, (syscall_function *) sys_write},
      {2, (syscall_function *) sys_seek},
      {1, (syscall_function *) sys_tell},
      {1, (syscall_function *) sys_close},
    };

  uint32_t call_num;
  uint32_t argv[3];

  /* Get the system call. */
  verify_address (f->esp);
  memcpy (&call_num, f->esp, sizeof (call_num));
  if (call_num >= NUM_SYSCALL)
    {
      thread_exit ();
    }
  
  /* Get the system call arguments. */
  for (uint8_t i = 0; i < syscall_table[call_num].arg_cnt; i++)
    {
      verify_address ((uint32_t *) f->esp + i + 1);
    }
  memset (argv, 0, sizeof (argv));
  memcpy (argv, (uint32_t *) f->esp + 1,
          sizeof (argv[0]) * syscall_table[call_num].arg_cnt);
  
  /* Execute the system call and set the return value. */
  f->eax = syscall_table[call_num].func (argv);
}

/* Used to halt pintos. */
static uint32_t
sys_halt (uint32_t *argv UNUSED)
{
  shutdown_power_off ();
  
  return 0;
}

/* Exits current user program. */
static uint32_t
sys_exit (uint32_t *argv)
{
  uint32_t status = (uint32_t) argv[0];
  
  thread_current ()->wait_status->exit_code = status;
  thread_exit ();
  
  return 0;
}

/* Executes given program. */
static uint32_t
sys_exec (uint32_t *argv)
{
  const char *cmd_line = (const char *) argv[0];
  struct wait_status *child;
  pid_t pid;
  
  verify_address (cmd_line);
  pid = process_execute (cmd_line);
  
  child = get_child (pid);
  
  ASSERT (child != NULL);
  
  if (child->load.value != 1)
    sema_down (&child->load);
  
  pid = child->tid;
  
  return pid;
}

/* Waits on given process id. */
static uint32_t
sys_wait (uint32_t *argv)
{
  pid_t pid = (pid_t) argv[0];
  return (uint32_t) process_wait (pid);
}

/* Creates file with given name. */
static uint32_t
sys_create (uint32_t *argv)
{
  const char *file = (const char *) argv[0];
  unsigned initial_size = (unsigned) argv[1];
  uint32_t ret;
  
  verify_address (file);
  
  lock_acquire (&fs_lock);
  ret = (uint32_t) filesys_create (file, initial_size);
  lock_release (&fs_lock);
  
  return ret;
}

/* Removes file with given name. */
static uint32_t
sys_remove (uint32_t *argv)
{
  const char *file = (const char *) argv[0];
  uint32_t ret;
  
  verify_address (file);
  
  lock_acquire (&fs_lock);
  ret = (uint32_t) filesys_remove (file);
  lock_release (&fs_lock);
  
  return ret;
}

/* Opens given file. */
static uint32_t
sys_open (uint32_t *argv)
{
  const char *file = (const char *) argv[0];
  
  verify_address (file);
  struct file_descriptor *fd = (struct file_descriptor*) malloc (sizeof (*fd));
  int handle = -1;
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      fd->file = filesys_open (file);
      if (fd->file != NULL)
        {
          struct thread *t = thread_current ();
          handle = fd->handle = t->next_handle++;
          list_push_front (&t->fds, &fd->elem);
        }
      else
        {
          free (fd);
        }
      lock_release (&fs_lock);
    }
  
  return (uint32_t) handle;
}

/* Returns size of given file. */
static uint32_t
sys_filesize (uint32_t *argv)
{
  int handle = (int) argv[0];
  struct file_descriptor *fd = get_fd (handle);
  uint32_t ret = -1;
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      ret = (uint32_t) file_length (fd->file);
      lock_release (&fs_lock);
    }
  
  return ret;
}

/* Reads given file size into buffer from file fd.
   If handle is 0, read from console. */
static uint32_t
sys_read (uint32_t *argv)
{
  int handle = (int) argv[0];
  void *buffer = (void *) argv[1];
  unsigned size = (unsigned) argv[2];
  uint32_t ret = -1;
  
  verify_address (buffer);
  verify_address (buffer + size);
  
  if (handle == STDIN_FILENO)
    {
      uint8_t *c = (uint8_t *) buffer;
      for(uint32_t i = 0; i < size; i++)
        {
          *c = input_getc ();
          c++;
        }
      ret = size;
    }
  else
    {
      struct file_descriptor *fd = get_fd (handle);
      if (fd != NULL)
        {
          lock_acquire (&fs_lock);
          ret = (uint32_t) file_read_at (fd->file, buffer, size, file_tell (fd->file));
          lock_release (&fs_lock);
        }
    }
  
  return ret;
}

/* Writes SIZE bytes to FD.
   FD 1 writes to console. */
static uint32_t
sys_write (uint32_t *argv)
{
  uint32_t handle = (uint32_t) argv[0];
  const char *buffer = (const char *) argv[1];
  unsigned size = (unsigned) argv[2];
  uint32_t ret = -1;
  
  verify_address (buffer);
  verify_address (buffer + size);
  
  if (handle == STDOUT_FILENO)
    {
      uint32_t max_buff = 256;
      unsigned size_rem = size % 256;
      uint32_t i;

      for (i = 0; i < size / max_buff; i++)
        {
          putbuf (buffer + i * max_buff, max_buff);
        }
      putbuf (buffer + i * max_buff, size_rem);
      ret = size;
    }
  else
    {
      struct file_descriptor *fd = get_fd (handle);
      if (fd != NULL)
        {
          lock_acquire (&fs_lock);
          ret = (uint32_t) file_write_at (fd->file, buffer, size, file_tell (fd->file));
          lock_release (&fs_lock);
        }
    }
  
  return ret;
}

/* Changes next byte to be read or written. */
static uint32_t
sys_seek (uint32_t *argv)
{
  int handle = (int) argv[0];
  unsigned position = (unsigned) argv[1];
  struct file_descriptor *fd = get_fd (handle);
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      file_seek (fd->file, position);
      lock_release (&fs_lock);
    }
  
  return 0;
}

/* Returns position of next byte to be read or written. */
static uint32_t
sys_tell (uint32_t *argv)
{
  int handle = (int) argv[0];
  struct file_descriptor *fd = get_fd (handle);
  unsigned ret = -1;
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      ret = (unsigned) file_tell (fd->file);
      lock_release (&fs_lock);
    }

  return ret;
}

/* Closes current file. */
static uint32_t
sys_close (uint32_t *argv)
{
  int handle = (int) argv[0];
  struct file_descriptor *fd = get_fd (handle);
  
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      file_close (fd->file);
      lock_release (&fs_lock);
      list_remove (&fd->elem);
      free (fd);
    }
  
  return 0;
}

/* Verifies the given virtual address.
   Exits the process if it is invalid. */
static void
verify_address (const void *vaddr)
{
  uint32_t *pd = thread_current ()->pagedir;
  void *end_add;
  
  if (vaddr == NULL || !is_user_vaddr (vaddr) || pagedir_get_page (pd, vaddr) == NULL)
    {
      thread_exit ();
    }

  end_add = (uint8_t *) vaddr + 3;
  
  if (end_add == NULL || !is_user_vaddr (end_add) || pagedir_get_page (pd, end_add) == NULL)
    {
      thread_exit ();
    }
  
}

/* Finds file descriptor from given handle.
   Returns NULL if it does not exist. */
static struct file_descriptor* get_fd (int handle)
{
  struct thread *t = thread_current ();
  struct file_descriptor *temp;
  struct file_descriptor *fd = NULL;
  struct list_elem *e;
  
  /* Search list of fds for given fd. */
  for (e = list_begin (&t->fds); e != list_end (&t->fds); e = list_next (e))
    {
      temp = list_entry (e, struct file_descriptor, elem);
      if (temp->handle == handle)
        {
          fd = temp;
          break;
        }
    }
  
  return fd;
}
