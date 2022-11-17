#include "list.h"
#include "utility.h"

/*
单向链表,初始化,追加节点,删除节点,删除链表,遍历链表
*/
void initList(LinkedListPtr list)
{
  list->head = NULL;
  list->current = NULL;
  list->tail = NULL;
  list->size = 0;
}

int appendNode(LinkedListPtr list,void* data)
{
NodePtr node = (NodePtr)malloc(sizeof(Node));

if (node == NULL)
    return -1;

node->data = data;
node->next = NULL;

if (list->head == NULL)
{
    list->head = node;
}
else
{
    list->tail->next = node;
}

list->tail = node;

return list->size++;
}

/* 
使用二级指针来指向链表的HEAD 
如果传递过来的node是头的话，p指向node的下一个节点
如果传递过来的node不是头的话,p指向list->node->next

总结: 
二级指针让head指针和next指针在某个特点上处于同一水平。
head指针和next最大的不同点是next指针能被别的指针操作。
因为next指针属于node结构体中，所以指向node结构体的指针可以携带操作next指针。
而head指针没有，没有指针指向它，要修改head的值或者读取head，需要在代码中写明head。
*/
void removeNode(LinkedListPtr list,NodePtr node)
{
NodePtr* p=&list->head;

while(*p != node)
	p = &(*p)->next;

  *p = node->next;

  util_free((void*)node);
  list->size--;
}

void displayList(LinkedListPtr list,DISPLAY display)
{
  NodePtr current = list->head;
  
  while (current != NULL)
  {
    display(current->data);
    current = current->next;
  }
}

void destoryList(LinkedListPtr list,DESTORY destory) 
{
NodePtr curr = list->head;

for(;curr!=NULL;curr = list->head)
{
  destory(&curr->data);
  removeNode(list,curr);
}
}

NodePtr getNode(LinkedListPtr list,COMPARE compare,void* data)
{
NodePtr curr = list->head;
	
	while (curr != NULL)
	{
		if (compare(curr->data,data) == 0)
			return curr;
		else
			curr = curr->next;
	}

return NULL;
}

void processNode(LinkedListPtr list,PROCESS process)
{
NodePtr current = list->head;
int i=0;

while (current != NULL)
{
    process(current->data,&i);
    current = current->next;
    i++;
}

}

/* 
双向链表 初始化,追加节点,删除节点,删除链表,遍历链表(正序,倒序)
*/
void DList_init(DListPtr list) 
{
list->head = NULL;
list->tail = NULL;
list->curr = NULL;
list->size = 0;

return;
}

int DList_append(DListPtr list,void *data) 
{
DListElmtPtr new_element = (DListElmtPtr)malloc(sizeof(DListElmt));

if (new_element == NULL)
   return -1;

new_element->data = (void *)data;

if (list->head == NULL)
{
   list->head = new_element;
   new_element->prev = NULL;
}
else 
{
  new_element->prev = list->tail;
  list->tail->next = new_element;
}

new_element->next = NULL;
list->tail = new_element;

return list->size++;
}

void DList_remove(DListPtr list,DListElmtPtr node)
{ 
DListElmtPtr* p=&list->head;

while(*p != node)
	p = &(*p)->next;

  *p = node->next;

  util_free((void*)node);
  list->size--;  
}

void DList_destroy(DListPtr list,DESTORY destory)
{
DListElmtPtr curr = list->head;

for(;curr!=NULL;curr = list->head)
{
  destory(&curr->data);
  DList_remove(list,curr);
}
}

/*
功能: 正序打印
*/
void DList_dispAsce(DListPtr list,DISPLAY display)
{
  DListElmtPtr current = list->head;
  
  while (current != NULL)
  {
    display(current->data);
    current = current->next;
  }
}

/*
功能: 逆序打印
*/
void DList_dispDesc(DListPtr list,DISPLAY display)
{
  DListElmtPtr current = list->tail;
  
  while (current != NULL)
  {
    display(current->data);
    current = current->prev;
  }
}
