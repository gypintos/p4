#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
    bool isdir;                         /* Directory or not */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode, bool *isdir) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  /** NEW ADDED HERE **/
  inode_acquire_lock(dir_get_inode((struct dir *)dir));
  // struct inode* inp = dir_get_inode((struct dir *)dir);
  // inode_acquire_lock(inp);

  if (lookup (dir, name, &e, NULL)){
    *inode = inode_open (e.inode_sector);
    /** NEW ADDED HERE **/
    *isdir = e.isdir;
  }
  else
    *inode = NULL;
  /** NEW ADDED HERE **/
  inode_release_lock(dir_get_inode((struct dir *)dir));
  // inode_release_lock(inp);
  
  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
/** NEW ADDED HERE **/
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,bool isdir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  inode_acquire_lock(dir_get_inode(dir));
  // struct inode* inp = dir_get_inode((struct dir *)dir);
  // inode_acquire_lock(inp);

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
/** NEW ADDED HERE **/
  memset(&e, 0, sizeof e);

  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;

/** NEW ADDED HERE **/
  e.isdir = isdir;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs, /*lock acquired*/ true) == sizeof e;
  
  // success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  /** NEW ADDED HERE **/
  inode_release_lock(dir_get_inode(dir));
  // inode_release_lock(inp);
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;
  /** NEW ADDED HERE **/
  struct dir *dir_ = NULL;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  /** NEW ADDED HERE **/
  inode_acquire_lock(dir_get_inode(dir));
  // struct inode* inp = dir_get_inode((struct dir *)dir);
  // inode_acquire_lock(inp);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /** NEW ADDED HERE **/
  if (e.isdir) {
    dir_ = dir_open (inode);
    // if ((dir_ == NULL) || is_root_dir (dir_) || !is_dir_empty (dir_)
    //  || is_dir_in_use (dir_))
    if (!dir_ || 
        is_root_dir(dir_) ||
        !is_dir_empty(dir_) ||
        is_dir_in_use(dir_))
      goto done;
  }


  /* Erase directory entry. */
  e.in_use = false;
  // if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
  /** NEW ADDED HERE **/
  if (inode_write_at (dir->inode, &e, sizeof e, ofs, true) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  /** NEW ADDED HERE **/
  inode_release_lock(dir_get_inode(dir));
  // inode_release_lock(inp);
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}



/** NEW ADDED HERE **/


/* Returns true if the given directory DIR is the root directory
   otherwise false */
bool
is_root_dir (struct dir *dir)
{
  ASSERT (dir != NULL);
  block_sector_t t = inode_get_inumber(dir_get_inode (dir));
  return t == ROOT_DIR_SECTOR;
  // return inode_get_inumber (dir_get_inode (dir)) == ROOT_DIR_SECTOR;
}

/* Returns true if the given directory DIR contains no entries other
   than "." and "..", otherwise false */
bool
is_dir_empty (struct dir *dir)
{
  // struct dir_entry e;
  // size_t ofs;

  // ASSERT (dir != NULL);

  // for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
  //      ofs += sizeof e)
  // if (e.in_use
  //     && (strcmp (".", e.name) != 0)
  //   && (strcmp ("..", e.name) != 0))
  //   return false;

  // return true;

  ASSERT (dir != NULL);
  struct dir_entry de;
  size_t off = 0;
  while (inode_read_at(dir->inode, &de, sizeof de, off) == sizeof de){
    if (de.in_use && 
        strcmp(".", de.name) != 0 &&
        strcmp("..", de.name) != 0){
      return false;
    } 
    off += sizeof de;
  }
  return true;
}

/* Returns true if the given directory DIR is in use (i.e. opened by
   a process). otherwise false */
bool
is_dir_in_use (struct dir *dir)
{
  // ASSERT (dir != NULL);
  // struct inode* inode = dir_get_inode (dir);
  // int open_cnt = inode_get_open_cnt (inode);
  //  To examine the DIR we have to open it first, therefore open count
  //    is at least 1 
  // ASSERT (open_cnt >= 1);
  // return (open_cnt > 1);

  ASSERT (dir);
  int cnt = inode_get_open_cnt(dir_get_inode(dir));
  ASSERT (cnt >= 1);
  return cnt > 1;

}

