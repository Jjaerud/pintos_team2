/* tests/threads/final-test-v2.c */
#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/synch.h"

#define TRACE_LEN 100000
static char execution_trace[TRACE_LEN + 1];
static int trace_idx;
static struct lock trace_lock;
static struct semaphore h_done_sleeping; // H가 잠에서 깨어났다는 신호

/* 자신의 문자를 버퍼에 기록하고 즉시 양보하는 스레드 */
static void trace_thread(void *name_char) {
    char name = *(char *)name_char;

    while (trace_idx < TRACE_LEN) {
        lock_acquire(&trace_lock);
        if (trace_idx < TRACE_LEN) {
            execution_trace[trace_idx++] = name;
        }
        lock_release(&trace_lock);
        thread_yield();
    }
}

/* 높은 우선순위 스레드 */
static void high_prio_thread(void *name_char) {
    msg("High prio thread H going to sleep for 50 ticks...");
    timer_sleep(1); // M, L이 먼저 실행되도록 잠시 잠
    msg("High prio thread H woke up!");
    
    
    trace_thread(name_char);
}


void test_stride(void) {
    char names[] = {'H', 'M', 'L'}; // High, Medium, Low

    msg("Starting final trace test v2...");

    lock_init(&trace_lock);
    sema_init(&h_done_sleeping, 0); // 세마포어 0으로 초기화
    trace_idx = 0;

    /* 스레드 생성 */
    thread_create("High",   30, high_prio_thread,   &names[0]);
    thread_create("Medium", 20, trace_thread, &names[1]);
    thread_create("Low",    10, trace_thread, &names[2]);
    
    /* 모든 스레드가 TRACE_LEN을 채울 충분한 시간을 줌 */
    timer_sleep(2);

    /* 결과 확인 */
    execution_trace[trace_idx] = '\0';
    msg("--- Execution Trace ---");
    msg("%s", execution_trace);

    pass();
}