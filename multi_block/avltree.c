#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "avltree.h"

/*
    remove all nodes of an AVL tree
*/
void dispose(node* t)
{
    if( t != NULL )
    {
        dispose( t->left );
        dispose( t->right );
	free( t->data );
        free( t );
    }
}
 
/*
    find a specific node's key in the tree
*/
node* find(char * e, node* t )
{
    if( t == NULL )
        return NULL;
    if( strcmp(e, t->data) < 0)
        return find( e, t->left );
    else if( strcmp(e, t->data) > 0)
        return find( e, t->right );
    else
        return t;
}
 
/*
    find minimum node's key
*/
node* find_min( node* t )
{
    if( t == NULL )
        return NULL;
    else if( t->left == NULL )
        return t;
    else
        return find_min( t->left );
}
 
/*
    find maximum node's key
*/
node* find_max( node* t )
{
    if( t != NULL )
        while( t->right != NULL )
            t = t->right;
 
    return t;
}
 
/*
    get the height of a node
*/
static int height( node* n )
{
    if( n == NULL )
        return -1;
    else
        return n->height;
}
 
/*
    get maximum value of two integers
*/
static int max( int l, int r)
{
    return l > r ? l: r;
}
 
/*
    perform a rotation between a k2 node and its left child
 
    note: call single_rotate_with_left only if k2 node has a left child
*/
 
static node* single_rotate_with_left( node* k2 )
{
    node* k1 = NULL;
 
    k1 = k2->left;
    k2->left = k1->right;
    k1->right = k2;
 
    k2->height = max( height( k2->left ), height( k2->right ) ) + 1;
    k1->height = max( height( k1->left ), k2->height ) + 1;
    return k1; /* new root */
}
 
/*
    perform a rotation between a node (k1) and its right child
 
    note: call single_rotate_with_right only if
    the k1 node has a right child
*/
 
static node* single_rotate_with_right( node* k1 )
{
    node* k2;
 
    k2 = k1->right;
    k1->right = k2->left;
    k2->left = k1;
 
    k1->height = max( height( k1->left ), height( k1->right ) ) + 1;
    k2->height = max( height( k2->right ), k1->height ) + 1;
 
    return k2;  /* New root */
}
 
/*
 
    perform the left-right double rotation,
 
    note: call double_rotate_with_left only if k3 node has
    a left child and k3's left child has a right child
*/
 
static node* double_rotate_with_left( node* k3 )
{
    /* Rotate between k1 and k2 */
    k3->left = single_rotate_with_right( k3->left );
 
    /* Rotate between K3 and k2 */
    return single_rotate_with_left( k3 );
}
 
/*
    perform the right-left double rotation
 
   notes: call double_rotate_with_right only if k1 has a
   right child and k1's right child has a left child
*/
 
 
 
static node* double_rotate_with_right( node* k1 )
{
    /* rotate between K3 and k2 */
    k1->right = single_rotate_with_left( k1->right );
 
    /* rotate between k1 and k2 */
    return single_rotate_with_right( k1 );
}
 
/*
    insert a new node into the tree
*/
node* insert( char * e, node* t )
{
    if( t == NULL )
    {
        /* Create and return a one-node tree */
        t = (node*)malloc(sizeof(node));
        if( t == NULL )
        {
            fprintf (stderr, "Out of memory!!! (insert)\n");
            exit(1);
        }
        else
        {
            t->data = (char *)malloc(strlen(e)+1);
	    strcpy(t->data, e);
            t->height = 0;
            t->left = t->right = NULL;
        }
    }
    else if( strcmp(e, t->data) < 0 )
    {
        t->left = insert( e, t->left );
        if( height( t->left ) - height( t->right ) == 2 )
            if( strcmp(e, t->left->data) < 0 )
                t = single_rotate_with_left( t );
            else
                t = double_rotate_with_left( t );
    }
    else if( strcmp(e, t->data) > 0 )
    {
        t->right = insert( e, t->right );
        if( height( t->right ) - height( t->left ) == 2 )
            if( strcmp(e, t->right->data) > 0 )
                t = single_rotate_with_right( t );
            else
                t = double_rotate_with_right( t );
    }
    /* Else X is in the tree already; we'll do nothing */
 
    t->height = max( height( t->left ), height( t->right ) ) + 1;
    return t;
}
 
/*
    remove a node in the tree

node* delete( char * e, node* t )
{
    printf( "Sorry; Delete is unimplemented; %s remains\n", e );
    return t;
}
*/
 
/*
    data data of a node
*/
char * get(node* n)
{
    return n->data;
}
 
/*
    Recursively display AVL tree or subtree
*/
void display_avl(node* t)
{
    if (t == NULL)
        return;
    printf("%s",t->data);
 
    if(t->left != NULL)
        printf("(L:%s)",t->left->data);
    if(t->right != NULL)
        printf("(R:%s)",t->right->data);
    printf("(height:%d)",t->height);
    printf("\n");
 
    display_avl(t->left);
    display_avl(t->right);
}
