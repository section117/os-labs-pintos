#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "kernel/stdio.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

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
int filesize(int fd);
unsigned tell(int fd);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
void close(int fd);
int open(const char *file);
int read(int fd, void *buffer, unsigned size);
pid_t exec(const char* cmd_line);
int isValidUser(void* pointer, void* destination, size_t size);
int wait(pid_t pid);



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

  case SYS_EXEC: {
    const char* cmd_line;
    
    if(isValidUser(f->esp + 4, &cmd_line, sizeof(cmd_line)) == -1) {
      exit(-1);
    }
    f->eax =  exec(cmd_line);
    break;
  }
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

    if(isValidUser(f->esp + 8, &position, sizeof(position)) == -1) {
      exit(-1);
    }
    seek(fd, position);
    break;
  }

  case SYS_CREATE:{
    char* file;
    unsigned initial_size;

    if(isValidUser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    if(isValidUser(f->esp + 8, &initial_size, sizeof(initial_size)) == -1) {
      exit(-1);
    }
    f->eax = create(file, initial_size);
    break;
  }

  case SYS_REMOVE:{
    char* file;
    if(isValidUser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    f->eax = remove(file);
    break;
  }

  case SYS_OPEN: {
    char* file;
    if(isValidUser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)open(file);
    break;
  }
  
  case SYS_FILESIZE:{
    int fd;
    if(isValidUser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)filesize(fd);
    break;
  }

  case SYS_READ: {
    int fd;
    void * buffer;
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

    f->eax = (uint32_t)read(fd, buffer, size);
    break;
  }

  case SYS_TELL: {
    int fd;
    if(isValidUser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)tell(fd);
    break;
  }

  case SYS_CLOSE: {
    int fd;
    if(isValidUser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    close(fd);
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

    if ((void*)uaddr >= PHYS_BASE)
      return -1; 
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
    *(char*) (destination + j) = value & 0xff;
  }
  return (int) size;
}


int write(int fd, const void *buffer, unsigned size){
  // if(fd==0 || fd == 2) return -1;

  if (get_user(buffer) == -1 || get_user(buffer + size) == -1) exit(-1);  
  
  if(fd == 1){
    putbuf((const char*)buffer, size);
    return size;
  }

  struct file_descripter* file_des = getFileDes(fd);

  if(file_des == NULL){
    return -1;
  }
  lock_acquire(&locker);

  int bytes_written = (int) file_write(file_des->file, buffer, size);

  lock_release(&locker);
  
  return bytes_written;
}


void exit (int status)
{
    struct thread *cur = thread_current (); 
    
    cur->t_pcb->exitcode = status;
    printf("%s: exit(%d)\n" , cur -> name , status);
    thread_exit();
} 


int wait(pid_t pid) {
  return process_wait(pid);
}


void seek(int fd, unsigned position) {
  struct file_descripter* file_des = getFileDes(fd);
  if(file_des == NULL) return;
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

int filesize(int fd){
  struct file_descripter* file_des = getFileDes(fd);
  if(file_des == NULL) return -1;
  lock_acquire(&locker);
  off_t length = file_length(file_des->file);
  lock_release(&locker);
  return length;
}


unsigned tell(int fd){
  struct file_descripter* file_des = getFileDes(fd);
  if(file_des == NULL) return -1;
  lock_acquire(&locker);
  off_t t = file_tell(file_des->file);
  lock_release(&locker);
  return t;
}


bool create(const char *file, unsigned initial_size){
  if (get_user(file) == -1) exit(-1); 
  lock_acquire(&locker);
  bool file_status = filesys_create(file, initial_size);
  lock_release(&locker);
  return file_status;
}

bool remove(const char *file){
  lock_acquire(&locker);
  bool removed = filesys_remove(file);
  lock_release(&locker);
  return removed;
}


void close(int fd) {
  struct file_descripter* file_des = getFileDes(fd);
  if(file_des == NULL) return;
  lock_acquire(&locker);
  file_close(file_des->file);
  list_remove(&file_des->elem);
  free(file_des);
  lock_release(&locker); 
}

int open(const char *file){

  if(file == NULL) return -1;

  lock_acquire(&locker);

  struct file* f = filesys_open(file);

  /* If no file was created, then return -1. */
  if(f == NULL)
  {
    lock_release(&locker);
    return -1;
  }

  /* Create a struct to hold the file/fd, for use in a list in the current process.
     Increment the fd for future files. Release our lock and return the fd as an int. */
  struct file_descripter *new_file = malloc(sizeof(struct file_descripter));
  new_file->file = f;
  struct list* file_list = &thread_current()->file_list;
  if(list_empty(file_list)){
    new_file->id = 3;
  }else{
    struct file_descripter* file_des = list_entry(list_back(file_list), struct file_descripter, elem);
    new_file->id = file_des->id + 1;
  }
  
  list_push_back(file_list, &new_file->elem);
  lock_release(&locker);

  return new_file->id;
}


int read(int fd, void *buffer, unsigned size){

  if (get_user(buffer) == -1 || get_user(buffer + size - 1) == -1) exit(-1); 

  lock_acquire(&locker);
  if (fd == 0)
  {
    lock_release(&locker);
    return (int) input_getc();
  }

  if (fd == 1 || fd == 2 || list_empty(&thread_current()->file_list))
  {
    lock_release(&locker);
    return -1;
  }

  struct list_elem *temp;

  for (temp = list_front(&thread_current()->file_list); temp != NULL; temp = temp->next)
  {
      struct file_descripter *t = list_entry(temp, struct file_descripter, elem);
      if (t->id == fd)
      {
        lock_release(&locker);
        int bytes = (int) file_read(t->file, buffer, size);
        return bytes;
      }
  }

  lock_release(&locker);
  ////
  return -1;
}

pid_t exec(const char* cmd_line) {

  int i = 0; 
  while (i < sizeof(cmd_line)) { 
    if (get_user(cmd_line + i) == -1){ 
      exit(-1); 
    } 
    i++; 
  } 
  if(!cmd_line)
	{
		return -1;
	}
  lock_acquire(&locker);
  /* Get and return the PID of the process that is created. */
	pid_t child_tid = process_execute(cmd_line);
  lock_release(&locker);
	return child_tid;
}




 //comment