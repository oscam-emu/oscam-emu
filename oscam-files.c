#include "globals.h"

#include "oscam-files.h"
#include "oscam-lock.h"
#include "oscam-string.h"

extern CS_MUTEX_LOCK readdir_lock;
extern char cs_tmpdir[200];

/* Gets the tmp dir */
char *get_tmp_dir(void)
{
    if (cs_tmpdir[0])
        return cs_tmpdir;
#if defined(__CYGWIN__)
    char *d = getenv("TMPDIR");
    if (!d || !d[0])
        d = getenv("TMP");
    if (!d || !d[0])
        d = getenv("TEMP");
    if (!d || !d[0])
        getcwd(cs_tmpdir, sizeof(cs_tmpdir) - 1);

    cs_strncpy(cs_tmpdir, d, sizeof(cs_tmpdir));
    char *p = cs_tmpdir;
    while (*p) p++;
    p--;
    if (*p != '/' && *p != '\\')
        strcat(cs_tmpdir, "/");
    strcat(cs_tmpdir, "_oscam");
#else
    cs_strncpy(cs_tmpdir, "/tmp/.oscam", sizeof(cs_tmpdir));
#endif
    mkdir(cs_tmpdir, S_IRWXU);
    return cs_tmpdir;
}

char *get_tmp_dir_filename(char *dest, size_t destlen, const char *filename)
{
    char *tmp_dir = get_tmp_dir();
    const char *slash = "/";
    if (tmp_dir[strlen(tmp_dir) - 1] == '/') slash = "";
    snprintf(dest, destlen, "%s%s%s", tmp_dir, slash, filename);
    return dest;
}

/* Drop-in replacement for readdir_r as some plattforms strip the function from their libc.
   Furthermore, there are some security issues, see http://womble.decadent.org.uk/readdir_r-advisory.html */
int32_t cs_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    /* According to POSIX the buffer readdir uses is not shared between directory streams.
       However readdir is not guaranteed to be thread-safe and some implementations may use global state.
       Thus we use a lock as we have many plattforms... */
    int32_t rc;
    cs_writelock(&readdir_lock);
    errno = 0;
    *result = readdir(dirp);
    rc = errno;
    if (errno == 0 && *result != NULL)
    {
        memcpy(entry, *result, sizeof(struct dirent));
        *result = entry;
    }
    cs_writeunlock(&readdir_lock);
    return rc;
}

/* Return 1 if the file exists, else 0 */
bool file_exists(const char *filename)
{
    return access(filename, R_OK) == 0;
}

/* Copies a file from srcfile to destfile. If an error occured before writing, -1 is returned, else -2. On success, 0 is returned.*/
int32_t file_copy(char *srcfile, char *destfile)
{
    FILE *src, *dest;
    int32_t ch;
    src = fopen(srcfile, "r");
    if (!src)
    {
        cs_log("Error opening file %s for reading (errno=%d %s)!", srcfile, errno, strerror(errno));
        return -1;
    }
    dest = fopen(destfile, "w");
    if (!dest)
    {
        cs_log("Error opening file %s for writing (errno=%d %s)!", destfile, errno, strerror(errno));
        fclose(src);
        return -1;
    }
    while (1)
    {
        ch = fgetc(src);
        if (ch == EOF)
        {
            break;
        }
        else
        {
            fputc(ch, dest);
            if (ferror(dest))
            {
                cs_log("Error while writing to file %s (errno=%d %s)!", destfile, errno, strerror(errno));
                fclose(src);
                fclose(dest);
                return -2;
            }
        }
    }
    fclose(src);
    fclose(dest);
    return (0);
}

/* Overwrites destfile with temp_file. If forceBakOverWrite = 0, the bakfile will not be overwritten if it exists, else it will be.*/
int32_t safe_overwrite_with_bak(char *destfile, char *temp_file, char *bakfile, int32_t forceBakOverWrite)
{
    int32_t rc;
    if (file_exists(destfile))
    {
        if (forceBakOverWrite != 0 || !file_exists(bakfile))
        {
            if (file_copy(destfile, bakfile) < 0)
            {
                cs_log("Error copying original config file %s to %s. The original config will be left untouched!", destfile, bakfile);
                if (remove(temp_file) < 0)
                    cs_log("Error removing temp config file %s (errno=%d %s)!", temp_file, errno, strerror(errno));
                return 1;
            }
        }
    }
    rc = file_copy(temp_file, destfile);
    if (rc < 0)
    {
        cs_log("An error occured while writing the new config file %s.", destfile);
        if (rc == -2)
            cs_log("The config will be missing or only partly filled upon next startup as this is a non-recoverable error! Please restore from backup or try again.");
        if (remove(temp_file) < 0)
            cs_log("Error removing temp config file %s (errno=%d %s)!", temp_file, errno, strerror(errno));
        return 1;
    }
    if (remove(temp_file) < 0)
        cs_log("Error removing temp config file %s (errno=%d %s)!", temp_file, errno, strerror(errno));
    return 0;
}
