// Mise en quarantaine

#ifndef AV_QUARANTINE_H
#define AV_QUARANTINE_H

#include <stdint.h>
#include <time.h>

#define QUARANTINE_MAGIC 0x4A4F484E504F524B

typedef struct {
    uint32_t magic;
    char original_path[256];
    char threat_name[64];
    time_t timestamp;
} QuarantineHeader;

/* Define quarantine directory
 * @param quarantine_dir: path to the quarantine folder (ex: "./quarantine")
 */
int quarantine_init(const char* quarantine_dir);

/* Isolates an infected file.
* Reads the file, encrypt it, writes the header and content to the quarantine folder, then deletes the original.
* @param original_filepath: the path to the infected file
* @param threat_name: the name of the detected malware
* @param out_quarantine_id: buffer that will receive the new name of the encrypted file
*/
int quarantine_file(const char* original_filepath, const char* threat_name, char* out_quarantine_id);

/* Restores a file from quarantine to a specified location.
* @param quarantine_id: the name of the file in the quarantine folder
* @param restore_path: the full path where the file is to be restored in its original form
*/
int quarantine_restore(const char* quarantine_id, const char* restore_path);

#endif // AV_QUARANTINE_H