#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int
get_user (const uint8_t *uaddr)
{
  int result;
  // asm -> 명령어1; 명령어2; ... : 출력 피연산자 : 입력 피연산자
  // 출력 피연산자 = result (eax 레지스터)
  // 입력 피연산자 = *uaddr (사용자 메모리 주소)

  // 명령어1
  // movl $1f, %0 = 4byte 데이터 $1f (= 1: 레이블 주소) mov(복사) to %0 (첫 피연산자=출력)
  // 따라서 1: 레이블 주소를 eax에 복사(mov) 하는 과정
  // ## 정상 경우 레이블은 의미 없는 부분이다.
  // ## 왜냐하면 이땐 다음 어셈블리 코드에서 eax에 uaddr에서 1바이트 읽은 값이 저장되니까!
  // ## 만약 page_fault가 발생한다면 movzbl(명령어2)에서 발생할 것이다.
  // ## 그리고 eax에 레이블 주소가 있는 상태로 page_fault 함수로 넘어가는데
  // ## page_fault함수에서 eip에 이 레이블 주소를 넣고 eax에 -1을 넣는다
  // ## 그래서 이 경우 get_user의 리턴은 -1이다
  // 이때 1: 레이블은 어셈블리 명령어 수행 이후 (; 이후) 정의되어 있으니
  // 리턴되면 이후 수행되는 어셈블리 코드가 없으니 asm 종료
  // 명령어2
  // movzbl %1, %0 = 1바이트 데이터를 4바이트로 확장하고 0으로 padding 하여 mov(카피)
  // %1은 두 번째 피연산자(=입력 피연산자 = *uaddr)이므로 이걸 eax에 mov(카피)
  // 다시 말해서 uaddr주소 일부를 읽어서 eax레지스터에 저장하는 실제 메모리 접근하는 과정

  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  
  // 리턴되면 
  // 정상 상황 : uaddr 주소에서 읽은 1 바이트
  // page_fault : -1
  // 다만 이 함수가 호출되서 동작하는 시점은 모드 스위치는 일어났어도
  // 프로세스 스위치는 일어나지 않았으니 uaddr을 현재 프로세스의 페이지
  // 테이블을 바탕으로 MMU가 주소를 계산하는데 여기서 커널 영역을 침범하는 등 
  // 잘못된 주소인 경우 page_fault가 발생한다. (사용자 가상 주소 = 0 ~ PHYS_BASE)
  // 미리 수정한 핸들러인 page_fault 함수에서 이 경우 eax에 0xffffffff를 넣었으니
  // 이 경우 result는 -1이다.
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

void 
validate_addr(const void *addr)
{
  // addr이 user영역인지 체크
  // user영역이라도 할당되지 않은 메모리 접근인지 체크
  // 만약 user영역이라면 get_user를 통해 불러올텐데 여기서 문제 발생시
  // page fault 발생하여 해당 핸들러 함수로 이동하는데 이때 page_fault에 의해
  // kill()이 수행되면 안된다! (커널 패닉 일어나니까) -> -1을 return하도록 수정했음!
  if (!is_user_vaddr(addr) || get_user(addr) == -1) 
  {
    exit(-1);
  }
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf("syscall num : %d\n", *(uint32_t*)(f->esp));
  validate_addr(f->esp);

  switch(*(uint32_t*)(f->esp)){
    case SYS_HALT:
    halt();
    break;

    case SYS_EXIT:
    validate_addr(f->esp+4);
    exit(*(uint32_t*)(f->esp+4));
    break;

    case SYS_EXEC:
    validate_addr(f->esp+4);
    f->eax = exec((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_WAIT:
    validate_addr(f->esp+4);
    f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
    break;

    case SYS_CREATE:
    validate_addr(f->esp+4);
    validate_addr(f->esp+8);
    f->eax = create((char*)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
    break;

    case SYS_REMOVE:
    validate_addr(f->esp+4);
    f->eax = remove((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_OPEN:
    validate_addr(f->esp+4);
    f->eax = open((char*)*(uint32_t*)(f->esp+4));
    break;

    case SYS_FILESIZE:
    validate_addr(f->esp+4);
    f->eax = filesize((int)*(uint32_t*)(f->esp+4));
    break;

    case SYS_READ:
    validate_addr(f->esp+4);
    validate_addr(f->esp+8);
    validate_addr(f->esp+12);
    f->eax = read((int)*(uint32_t*)(f->esp+4),(void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
    break;

    case SYS_WRITE:
    validate_addr(f->esp+4);
    validate_addr(f->esp+8);
    validate_addr(f->esp+12);
    f->eax = write((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8), (unsigned)*(uint32_t*)(f->esp+12));
    break;
    
    case SYS_SEEK:
    validate_addr(f->esp+4);
    validate_addr(f->esp+8);
    seek((int)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
    break;

    case SYS_TELL:
    validate_addr(f->esp+4);
    f->eax = tell((unsigned)*(uint32_t*)(f->esp+4));
    break;

    case SYS_CLOSE:
    validate_addr(f->esp+4);
    close((int)*(uint32_t*)(f->esp+4));
    break;
  }

  //printf ("system call!\n");

  //thread_exit ();
}

// ------------ process management --------------

// SYS_HALT = 0 args
void halt(void)
{
  shutdown_power_off();
}

// SYS_EXIT = 1 args
void exit(int status)
{
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

// SYS_EXEC = 1 args
pid_t exec(const char *cmd_line)
{
  validate_addr(cmd_line);
  return process_execute(cmd_line);
}

// SYS_WAIT = 1 args
int wait (pid_t pid)
{
  return process_wait(pid);
}

// -----------------------------------------------






// ------------ file management ------------------

// SYS_CREATE = 2 args
bool create (const char *file, unsigned initial_size)
{
  if(file == NULL){
    exit(-1);
  }
  validate_addr(file);
  
  return filesys_create(file, initial_size);
}

// SYS_REMOVE = 1 args
bool remove (const char *file)
{
  validate_addr(file);
  return filesys_remove(file);
}

// SYS_OPEN = 1 args
int open (const char *file)
{
  if(file==NULL){
    exit(-1);
  }
  validate_addr(file);
  
  struct file *f = filesys_open(file);
  if(f == NULL){
    return -1;
  }
  struct thread *t = thread_current();
  
  for(int i = 3; i<128; i++){
    if(t->fdt[i]==NULL){
      t->fdt[i] = f;
      return i;
    }
  }
  // FULL!
  file_close(f);
  return -1;
}

// SYS_FILESIZE = 1 args
int filesize (int fd)
{
  if(fd<3 || fd>127 || thread_current()->fdt[fd]==NULL){
    return -1;
  }
  return file_length(thread_current()->fdt[fd]);
}

// SYS_READ = 3 args
int read (int fd, void *buffer, unsigned size)
{
  for(char* ptr = buffer; ptr < buffer + size; ptr++){
    validate_addr(ptr);
  }

  int result = -1;

  if(fd == 0){
    int cnt = 0;
    for(int i = 0 ; i<size; i++){
      uint8_t c = input_getc();
      if(!put_user(buffer+i, c)){
        exit(-1);
      }
      cnt++;
      if(c == '\n'){
        break;
      }
    }
    result = cnt;
  }else if(fd<128 && fd>2){
    if(thread_current()->fdt[fd] != NULL){
      result = file_read(thread_current()->fdt[fd], buffer, size);
    }
  }
  
  return result;
  
}

// SYS_WRITE = 3 args
int write(int fd, const void* buffer, unsigned size)
{
  for(char* ptr = buffer; ptr < buffer + size; ptr++){
    validate_addr(ptr);
  }
  int result = -1;
  if (fd == 1){
    putbuf(buffer, size);
    result = size;
  }else if(fd>2 && fd<128){
    if(thread_current()->fdt[fd]!=NULL){
      
        result = file_write(thread_current()->fdt[fd], buffer, size);
      
    }
  }
  return result;
}
// SYS_SEEK = 2 args
void seek (int fd, unsigned position)
{
  if(fd<3 || fd>127 || thread_current()->fdt[fd]==NULL){
    return;
  }

  file_seek(thread_current()->fdt[fd], position);
}

// SYS_TELL = 1 args
unsigned tell (int fd)
{
  if(fd<3 || fd>127 || thread_current()->fdt[fd]==NULL){
    return -1;
  }
  return file_tell(thread_current()->fdt[fd]);
}

// SYS_CLOSE = 1 args
void close (int fd)
{
  if(fd<3 || fd>127 || thread_current()->fdt[fd]==NULL){
    return;
  }
  file_close(thread_current()->fdt[fd]);
  thread_current()->fdt[fd] = NULL;
}

// -----------------------------------------------
