#ifndef __avltree_h__

typedef struct node
{
    char * data;
    struct node*  left;
    struct node*  right;
    int height;
} node;
 
void dispose(node* t);
node* find( char * e, node *t );
node* find_min( node *t );
node* find_max( node *t );
node* insert( char * data, node *t );
void display_avl(node* t);
char * get( node* n );
#endif
