#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "devices/timer.h"

#define THREAD_CNT 3
/* 0: High-Prio Sleeper, 1: Low-Prio Worker */
static volatile unsigned long long counter[THREAD_CNT];

/* CPU를 계속 사용하며 카운터를 증가시키는 함수 */
static void worker_thread(void *aux) {
    int id = *(int *)aux;
    while (true) {
        counter[id]++;
    }
}

/* 생성되자마자 잠드는, 높은 우선순위 스레드 */
static void high_prio_sleeper(void *aux) {
    msg("thread starts and sleeps for 500 ticks.");
    timer_sleep(500);
    msg("thread woke up! Starts working.");
    worker_thread(aux);
}

/* 메인 테스트 함수 */
void test_thread_new(void) {
    int ids[THREAD_CNT] = {0, 1, 2};

    msg("Starting final test to verify 'remain' logic...");

    /* 1. LowPrio Worker를 먼저 생성하고 100틱 동안 실행시켜
          시스템의 pass 값을 충분히 높여놓는다. */
    thread_create("LowWorker",   10, worker_thread,     &ids[1]);
    timer_sleep(1000);

    /* 2. HighPrio Sleeper를 동적으로 생성한다. 이 스레드는 바로 잠든다. */
    msg("--- Creating HighPrio Sleeper ---");
    thread_create("HighSleeper", 60, high_prio_sleeper, &ids[0]);

    /* 3. 전체 테스트가 끝날 때까지 300틱 더 기다린다.
          이 시간 동안 High는 200틱 자고 100틱 일하게 된다.
          Low는 300틱 내내 일한다. */
    timer_sleep(1000);


    msg("--- Creating midPrio Sleeper ---");
    thread_create("minimumSleeper", 1, high_prio_sleeper, &ids[2]);

    timer_sleep(1500);

    /* 4. 결과 확인 */
    msg("--- Test Results ---");
    msg("HighPrio Sleeper counter: %llu", counter[0]);
    msg("LowPrio Worker  counter: %llu", counter[1]);
    msg("minPrio Worker  counter: %llu", counter[2]);
    
    pass();
}