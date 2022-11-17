#ifndef __LIST_H
#define __LIST_H

#include <stdio.h>
#include <stdlib.h>

typedef void(*DISPLAY)(void*);
typedef void(*DESTORY)(void**);
typedef int(*COMPARE)(void*,void*);
typedef void(*PROCESS)(void*,void*);

/* 单向链表 */
typedef struct _node{
    void *data;
    struct _node *next;
}Node,*NodePtr;

typedef struct _linkedList{
    NodePtr head;
    NodePtr tail;
    NodePtr current;
    int size;
}LinkedList,*LinkedListPtr;

/* 双向链表 */
typedef struct _DListElmt {
    void               *data;
    struct _DListElmt  *prev;
    struct _DListElmt  *next;
}DListElmt,*DListElmtPtr;

typedef struct _DList {
    DListElmtPtr head;
    DListElmtPtr tail;
    DListElmtPtr curr;
    int size;
}DList,*DListPtr;

/* 单向链表 */
void initList(LinkedListPtr);
int appendNode(LinkedListPtr ,void* );
void removeNode(LinkedListPtr ,NodePtr );
void displayList(LinkedListPtr,DISPLAY );
void destoryList(LinkedListPtr,DESTORY );
NodePtr getNode(LinkedListPtr ,COMPARE ,void* data);
void processNode(LinkedListPtr ,PROCESS);

/* 双向链表 */
void DList_init(DListPtr);
int DList_append(DListPtr, void *);
void DList_destroy(DListPtr ,DESTORY );
void DList_dispAsce(DListPtr,DISPLAY );
void DList_dispDesc(DListPtr,DISPLAY );

#endif