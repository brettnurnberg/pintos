#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#define NUM_SYSCALL 13

static void syscall_handler (struct intr_frame *);
static void verify_address (const void *);

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

/* Initializes system call functionality */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  memcpy (&call_num, f->esp, sizeof (call_num));
  if (call_num >= NUM_SYSCALL)
    {
      thread_exit ();
    }
  
  /* Get the system call arguments. */
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
  uint32_t status = argv[0];
  
  thread_current ()->wait_status->exit_code = status;
  thread_exit ();
  
  return 0;
}

static uint32_t
sys_exec (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_wait (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_create (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_remove (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_open (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_filesize (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_read (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

/* Writes SIZE bytes to FD.
   FD 1 writes to console. */
static uint32_t
sys_write (uint32_t *argv)
{
  uint32_t fd = argv[0];
  const char *buffer = (char *) argv[1];
  unsigned size = argv[2];
  
  uint32_t max_buff = 256;
  unsigned size_rem = size % 256;
  uint32_t i;
  
  verify_address (buffer);
  //might need to verify end of buffer?
  
  if (fd == STDOUT_FILENO)
    {
      for (i = 0; i < size / max_buff; i++)
        {
          putbuf (buffer + i * max_buff, max_buff);
        }
      putbuf (buffer + i * max_buff, size_rem);
      return size;
    }
  else
    {
      //write to file descriptor fd
      return size;
    }
  
}

static uint32_t
sys_seek (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_tell (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

static uint32_t
sys_close (uint32_t *argv UNUSED)
{
  printf ("System call not implemented.\nHalting Pintos.\n");
  shutdown_power_off ();
  
  return 0;
}

/* Verifies the given virtual address.
   Exits the process if it is invalid. */
static void
verify_address (const void *vaddr)
{
  uint32_t *pd = thread_current ()->pagedir;
  if (vaddr == NULL || !is_user_vaddr (vaddr) || pagedir_get_page (pd, vaddr) == NULL)
    {
      thread_exit ();
    }
  
}
