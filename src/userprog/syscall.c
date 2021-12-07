#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "kernel/stdio.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/synch.h"

typedef int pid_t;

struct lock locker;

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
void halt(void);
int write(int fd, const void *buffer, unsigned size);
void exit (int status);
void seek(int fd, unsigned position);
struct file_descripter* getFileDes(int fd);



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&locker);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int number;
  if(isValidUser(f->esp, &number, sizeof(number)) == -1) {
    exit(-1);
  }
  switch (number)
  {
  case SYS_HALT:{
    halt();
    break;
  }
  
  case SYS_WRITE:{
    int fd;
    void* buffer;
    unsigned int size;

    if(isValidUser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }

    if(isValidUser(f->esp + 8, &buffer, sizeof(buffer)) == -1) {
      exit(-1);
    }

    if(isValidUser(f->esp + 12, &size, sizeof(size)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)write(fd, buffer, size);
    break;
  }

  case SYS_EXIT:{
    int status;
    if(isValidUser(f->esp + 4, &status, sizeof(status)) == -1) {
      exit(-1);
    }
    exit(status);
    break;
  }

  case SYS_WAIT: {
    pid_t pid;
    if(isValidUser(f->esp + 4, &pid, sizeof(pid)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)wait(pid);
    break;
  }

  case SYS_SEEK: {
    int fd;
    unsigned position;
    if(isValidUser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }

    if(isValidUser(f->esp + 4, &position, sizeof(position)) == -1) {
      exit(-1);
    }
    seek(fd, position);
    break;
  }
  
  default:{
    printf("not working");
    break;
  }
  }
  // printf ("system call!\n");
  // thread_exit ();
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE. 
   Returns true if successful, false if a segfault occurred.*/
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

void halt(void) {
  shutdown_power_off();
}

int isValidUser(void* pointer, void* destination, size_t size) {
  int32_t  value;
  size_t j;
  for(j = 0; j < size; j++){
    value = get_user(pointer + j);
    if(value == -1){
      exit(-1);
    }
    *(char*) (destination + j) = value&0xff;
  }
  return (int) size;
}


int write(int fd, const void *buffer, unsigned size){
  if(fd == 1){
    putbuf((const char*)buffer, size);
    return size;
  }
  return -1;
}


void exit (int status)
{
    struct thread *cur = thread_current (); 
    /* Save exit status at process descriptor */
    printf("%s: exit(%d)\n" , cur -> name , status);
    thread_exit();
} 


int wait(pid_t pid) {
  return process_wait(pid);
}


void seek(int fd, unsigned position) {
  struct file_descripter* file_des = getFileDes(fd);
  if(file_des == NULL) return -1;
  lock_acquire(&locker);
  file_seek(file_des->file, position);
  lock_release(&locker);
}

struct file_descripter* getFileDes(int fd) {
  // struct list* file_list = &thread_current()->file_list;
  if(fd < 3){
    return NULL;
  }
  
  // struct thread* curr_t = thread_current();
  struct list* file_list = &thread_current()-> file_list;
  struct list_elem *e;
  for (e = list_begin (file_list); e != list_end(file_list); e = list_next (e)){
    struct file_descripter* file_des = list_entry(e, struct file_descripter, elem);
    if(file_des->id == fd){
      return file_des;
    }
  }
  return NULL;
}



