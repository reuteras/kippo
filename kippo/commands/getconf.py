# -*- coding: utf-8 -*-
# See the COPYRIGHT file for more information

from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_getconf(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() == '-a':
            self.do_getconf_a()
            return
        if len(self.args) == 0:
            self.do_getconf_help()
            return
        if len(self.args):
            self.do_getconf_var()

    def do_getconf_help(self):
        """No real help output."""
        self.honeypot.writeln("""Usage: getconf [-v specification] variable_name [pathname]
               getconf -a [pathname]""")

    def do_getconf_a(self):
        self.honeypot.writeln("""LINK_MAX                           65000
_POSIX_LINK_MAX                    65000
MAX_CANON                          255
_POSIX_MAX_CANON                   255
MAX_INPUT                          255
_POSIX_MAX_INPUT                   255
NAME_MAX                           255
_POSIX_NAME_MAX                    255
PATH_MAX                           4096
_POSIX_PATH_MAX                    4096
PIPE_BUF                           4096
_POSIX_PIPE_BUF                    4096
SOCK_MAXBUF                        
_POSIX_ASYNC_IO                    
_POSIX_CHOWN_RESTRICTED            1
_POSIX_NO_TRUNC                    1
_POSIX_PRIO_IO                     
_POSIX_SYNC_IO                     
_POSIX_VDISABLE                    0
ARG_MAX                            2097152
ATEXIT_MAX                         2147483647
CHAR_BIT                           8
CHAR_MAX                           127
CHAR_MIN                           -128
CHILD_MAX                          1024
CLK_TCK                            100
INT_MAX                            2147483647
INT_MIN                            -2147483648
IOV_MAX                            1024
LOGNAME_MAX                        256
LONG_BIT                           64
MB_LEN_MAX                         16
NGROUPS_MAX                        65536
NL_ARGMAX                          4096
NL_LANGMAX                         2048
NL_MSGMAX                          2147483647
NL_NMAX                            2147483647
NL_SETMAX                          2147483647
NL_TEXTMAX                         2147483647
NSS_BUFLEN_GROUP                   1024
NSS_BUFLEN_PASSWD                  1024
NZERO                              20
OPEN_MAX                           1024
PAGESIZE                           4096
PAGE_SIZE                          4096
PASS_MAX                           8192
PTHREAD_DESTRUCTOR_ITERATIONS      4
PTHREAD_KEYS_MAX                   1024
PTHREAD_STACK_MIN                  16384
PTHREAD_THREADS_MAX                
SCHAR_MAX                          127
SCHAR_MIN                          -128
SHRT_MAX                           32767
SHRT_MIN                           -32768
SSIZE_MAX                          32767
TTY_NAME_MAX                       32
TZNAME_MAX                         6
UCHAR_MAX                          255
UINT_MAX                           4294967295
UIO_MAXIOV                         1024
ULONG_MAX                          18446744073709551615
USHRT_MAX                          65535
WORD_BIT                           32
_AVPHYS_PAGES                      21339
_NPROCESSORS_CONF                  1
_NPROCESSORS_ONLN                  1
_PHYS_PAGES                        254536
_POSIX_ARG_MAX                     2097152
_POSIX_ASYNCHRONOUS_IO             200809
_POSIX_CHILD_MAX                   1024
_POSIX_FSYNC                       200809
_POSIX_JOB_CONTROL                 1
_POSIX_MAPPED_FILES                200809
_POSIX_MEMLOCK                     200809
_POSIX_MEMLOCK_RANGE               200809
_POSIX_MEMORY_PROTECTION           200809
_POSIX_MESSAGE_PASSING             200809
_POSIX_NGROUPS_MAX                 65536
_POSIX_OPEN_MAX                    1024
_POSIX_PII                         
_POSIX_PII_INTERNET                
_POSIX_PII_INTERNET_DGRAM          
_POSIX_PII_INTERNET_STREAM         
_POSIX_PII_OSI                     
_POSIX_PII_OSI_CLTS                
_POSIX_PII_OSI_COTS                
_POSIX_PII_OSI_M                   
_POSIX_PII_SOCKET                  
_POSIX_PII_XTI                     
_POSIX_POLL                        
_POSIX_PRIORITIZED_IO              200809
_POSIX_PRIORITY_SCHEDULING         200809
_POSIX_REALTIME_SIGNALS            200809
_POSIX_SAVED_IDS                   1
_POSIX_SELECT                      
_POSIX_SEMAPHORES                  200809
_POSIX_SHARED_MEMORY_OBJECTS       200809
_POSIX_SSIZE_MAX                   32767
_POSIX_STREAM_MAX                  16
_POSIX_SYNCHRONIZED_IO             200809
_POSIX_THREADS                     200809
_POSIX_THREAD_ATTR_STACKADDR       200809
_POSIX_THREAD_ATTR_STACKSIZE       200809
_POSIX_THREAD_PRIORITY_SCHEDULING  200809
_POSIX_THREAD_PRIO_INHERIT         200809
_POSIX_THREAD_PRIO_PROTECT         200809
_POSIX_THREAD_ROBUST_PRIO_INHERIT  
_POSIX_THREAD_ROBUST_PRIO_PROTECT  
_POSIX_THREAD_PROCESS_SHARED       200809
_POSIX_THREAD_SAFE_FUNCTIONS       200809
_POSIX_TIMERS                      200809
TIMER_MAX                          
_POSIX_TZNAME_MAX                  6
_POSIX_VERSION                     200809
_T_IOV_MAX                         
_XOPEN_CRYPT                       1
_XOPEN_ENH_I18N                    1
_XOPEN_LEGACY                      1
_XOPEN_REALTIME                    1
_XOPEN_REALTIME_THREADS            1
_XOPEN_SHM                         1
_XOPEN_UNIX                        1
_XOPEN_VERSION                     700
_XOPEN_XCU_VERSION                 4
_XOPEN_XPG2                        1
_XOPEN_XPG3                        1
_XOPEN_XPG4                        1
BC_BASE_MAX                        99
BC_DIM_MAX                         2048
BC_SCALE_MAX                       99
BC_STRING_MAX                      1000
CHARCLASS_NAME_MAX                 2048
COLL_WEIGHTS_MAX                   255
EQUIV_CLASS_MAX                    
EXPR_NEST_MAX                      32
LINE_MAX                           2048
POSIX2_BC_BASE_MAX                 99
POSIX2_BC_DIM_MAX                  2048
POSIX2_BC_SCALE_MAX                99
POSIX2_BC_STRING_MAX               1000
POSIX2_CHAR_TERM                   200809
POSIX2_COLL_WEIGHTS_MAX            255
POSIX2_C_BIND                      200809
POSIX2_C_DEV                       200809
POSIX2_C_VERSION                   
POSIX2_EXPR_NEST_MAX               32
POSIX2_FORT_DEV                    
POSIX2_FORT_RUN                    
_POSIX2_LINE_MAX                   2048
POSIX2_LINE_MAX                    2048
POSIX2_LOCALEDEF                   200809
POSIX2_RE_DUP_MAX                  32767
POSIX2_SW_DEV                      200809
POSIX2_UPE                         
POSIX2_VERSION                     200809
RE_DUP_MAX                         32767
PATH                               /bin:/usr/bin
CS_PATH                            /bin:/usr/bin
LFS_CFLAGS                         
LFS_LDFLAGS                        
LFS_LIBS                           
LFS_LINTFLAGS                      
LFS64_CFLAGS                       -D_LARGEFILE64_SOURCE
LFS64_LDFLAGS                      
LFS64_LIBS                         
LFS64_LINTFLAGS                    -D_LARGEFILE64_SOURCE
_XBS5_WIDTH_RESTRICTED_ENVS        XBS5_LP64_OFF64
XBS5_WIDTH_RESTRICTED_ENVS         XBS5_LP64_OFF64
_XBS5_ILP32_OFF32                  
XBS5_ILP32_OFF32_CFLAGS            
XBS5_ILP32_OFF32_LDFLAGS           
XBS5_ILP32_OFF32_LIBS              
XBS5_ILP32_OFF32_LINTFLAGS         
_XBS5_ILP32_OFFBIG                 
XBS5_ILP32_OFFBIG_CFLAGS           
XBS5_ILP32_OFFBIG_LDFLAGS          
XBS5_ILP32_OFFBIG_LIBS             
XBS5_ILP32_OFFBIG_LINTFLAGS        
_XBS5_LP64_OFF64                   1
XBS5_LP64_OFF64_CFLAGS             -m64
XBS5_LP64_OFF64_LDFLAGS            -m64
XBS5_LP64_OFF64_LIBS               
XBS5_LP64_OFF64_LINTFLAGS          
_XBS5_LPBIG_OFFBIG                 
XBS5_LPBIG_OFFBIG_CFLAGS           
XBS5_LPBIG_OFFBIG_LDFLAGS          
XBS5_LPBIG_OFFBIG_LIBS             
XBS5_LPBIG_OFFBIG_LINTFLAGS        
_POSIX_V6_ILP32_OFF32              
POSIX_V6_ILP32_OFF32_CFLAGS        
POSIX_V6_ILP32_OFF32_LDFLAGS       
POSIX_V6_ILP32_OFF32_LIBS          
POSIX_V6_ILP32_OFF32_LINTFLAGS     
_POSIX_V6_WIDTH_RESTRICTED_ENVS    POSIX_V6_LP64_OFF64
POSIX_V6_WIDTH_RESTRICTED_ENVS     POSIX_V6_LP64_OFF64
_POSIX_V6_ILP32_OFFBIG             
POSIX_V6_ILP32_OFFBIG_CFLAGS       
POSIX_V6_ILP32_OFFBIG_LDFLAGS      
POSIX_V6_ILP32_OFFBIG_LIBS         
POSIX_V6_ILP32_OFFBIG_LINTFLAGS    
_POSIX_V6_LP64_OFF64               1
POSIX_V6_LP64_OFF64_CFLAGS         -m64
POSIX_V6_LP64_OFF64_LDFLAGS        -m64
POSIX_V6_LP64_OFF64_LIBS           
POSIX_V6_LP64_OFF64_LINTFLAGS      
_POSIX_V6_LPBIG_OFFBIG             
POSIX_V6_LPBIG_OFFBIG_CFLAGS       
POSIX_V6_LPBIG_OFFBIG_LDFLAGS      
POSIX_V6_LPBIG_OFFBIG_LIBS         
POSIX_V6_LPBIG_OFFBIG_LINTFLAGS    
_POSIX_V7_ILP32_OFF32              
POSIX_V7_ILP32_OFF32_CFLAGS        
POSIX_V7_ILP32_OFF32_LDFLAGS       
POSIX_V7_ILP32_OFF32_LIBS          
POSIX_V7_ILP32_OFF32_LINTFLAGS     
_POSIX_V7_WIDTH_RESTRICTED_ENVS    POSIX_V7_LP64_OFF64
POSIX_V7_WIDTH_RESTRICTED_ENVS     POSIX_V7_LP64_OFF64
_POSIX_V7_ILP32_OFFBIG             
POSIX_V7_ILP32_OFFBIG_CFLAGS       
POSIX_V7_ILP32_OFFBIG_LDFLAGS      
POSIX_V7_ILP32_OFFBIG_LIBS         
POSIX_V7_ILP32_OFFBIG_LINTFLAGS    
_POSIX_V7_LP64_OFF64               1
POSIX_V7_LP64_OFF64_CFLAGS         -m64
POSIX_V7_LP64_OFF64_LDFLAGS        -m64
POSIX_V7_LP64_OFF64_LIBS           
POSIX_V7_LP64_OFF64_LINTFLAGS      
_POSIX_V7_LPBIG_OFFBIG             
POSIX_V7_LPBIG_OFFBIG_CFLAGS       
POSIX_V7_LPBIG_OFFBIG_LDFLAGS      
POSIX_V7_LPBIG_OFFBIG_LIBS         
POSIX_V7_LPBIG_OFFBIG_LINTFLAGS    
_POSIX_ADVISORY_INFO               200809
_POSIX_BARRIERS                    200809
_POSIX_BASE                        
_POSIX_C_LANG_SUPPORT              
_POSIX_C_LANG_SUPPORT_R            
_POSIX_CLOCK_SELECTION             200809
_POSIX_CPUTIME                     200809
_POSIX_THREAD_CPUTIME              200809
_POSIX_DEVICE_SPECIFIC             
_POSIX_DEVICE_SPECIFIC_R           
_POSIX_FD_MGMT                     
_POSIX_FIFO                        
_POSIX_PIPE                        
_POSIX_FILE_ATTRIBUTES             
_POSIX_FILE_LOCKING                
_POSIX_FILE_SYSTEM                 
_POSIX_MONOTONIC_CLOCK             200809
_POSIX_MULTI_PROCESS               
_POSIX_SINGLE_PROCESS              
_POSIX_NETWORKING                  
_POSIX_READER_WRITER_LOCKS         200809
_POSIX_SPIN_LOCKS                  200809
_POSIX_REGEXP                      1
_REGEX_VERSION                     
_POSIX_SHELL                       1
_POSIX_SIGNALS                     
_POSIX_SPAWN                       200809
_POSIX_SPORADIC_SERVER             
_POSIX_THREAD_SPORADIC_SERVER      
_POSIX_SYSTEM_DATABASE             
_POSIX_SYSTEM_DATABASE_R           
_POSIX_TIMEOUTS                    200809
_POSIX_TYPED_MEMORY_OBJECTS        
_POSIX_USER_GROUPS                 
_POSIX_USER_GROUPS_R               
POSIX2_PBS                         
POSIX2_PBS_ACCOUNTING              
POSIX2_PBS_LOCATE                  
POSIX2_PBS_TRACK                   
POSIX2_PBS_MESSAGE                 
SYMLOOP_MAX                        
STREAM_MAX                         16
AIO_LISTIO_MAX                     
AIO_MAX                            
AIO_PRIO_DELTA_MAX                 20
DELAYTIMER_MAX                     2147483647
HOST_NAME_MAX                      64
LOGIN_NAME_MAX                     256
MQ_OPEN_MAX                        
MQ_PRIO_MAX                        32768
_POSIX_DEVICE_IO                   
_POSIX_TRACE                       
_POSIX_TRACE_EVENT_FILTER          
_POSIX_TRACE_INHERIT               
_POSIX_TRACE_LOG                   
RTSIG_MAX                          32
SEM_NSEMS_MAX                      
SEM_VALUE_MAX                      2147483647
SIGQUEUE_MAX                       3921
FILESIZEBITS                       64
POSIX_ALLOC_SIZE_MIN               4096
POSIX_REC_INCR_XFER_SIZE           
POSIX_REC_MAX_XFER_SIZE            
POSIX_REC_MIN_XFER_SIZE            4096
POSIX_REC_XFER_ALIGN               4096
SYMLINK_MAX                        
GNU_LIBC_VERSION                   glibc 2.18
GNU_LIBPTHREAD_VERSION             NPTL 2.18
POSIX2_SYMLINKS                    1
LEVEL1_ICACHE_SIZE                 32768
LEVEL1_ICACHE_ASSOC                8
LEVEL1_ICACHE_LINESIZE             64
LEVEL1_DCACHE_SIZE                 32768
LEVEL1_DCACHE_ASSOC                8
LEVEL1_DCACHE_LINESIZE             64
LEVEL2_CACHE_SIZE                  2097152
LEVEL2_CACHE_ASSOC                 8
LEVEL2_CACHE_LINESIZE              64
LEVEL3_CACHE_SIZE                  0
LEVEL3_CACHE_ASSOC                 0
LEVEL3_CACHE_LINESIZE              0
LEVEL4_CACHE_SIZE                  0
LEVEL4_CACHE_ASSOC                 0
LEVEL4_CACHE_LINESIZE              0
IPV6                               200809
RAW_SOCKETS                        200809""")

    def do_getconf_var(self):
        getconf_dict={"LINK_MAX": "65000","_POSIX_LINK_MAX": "65000","MAX_CANON": "255","_POSIX_MAX_CANON": "255","MAX_INPUT": "255","_POSIX_MAX_INPUT": "255","NAME_MAX": "255","_POSIX_NAME_MAX": "255","PATH_MAX": "4096","_POSIX_PATH_MAX": "4096","PIPE_BUF": "4096","_POSIX_PIPE_BUF": "4096","SOCK_MAXBUF": "","_POSIX_ASYNC_IO": "","_POSIX_CHOWN_RESTRICTED": "1","_POSIX_NO_TRUNC": "1","_POSIX_PRIO_IO": "","_POSIX_SYNC_IO": "","_POSIX_VDISABLE": "0","ARG_MAX": "2097152","ATEXIT_MAX": "2147483647","CHAR_BIT": "8","CHAR_MAX": "127","CHAR_MIN": "-128","CHILD_MAX": "1024","CLK_TCK": "100","INT_MAX": "2147483647","INT_MIN": "-2147483648","IOV_MAX": "1024","LOGNAME_MAX": "256","LONG_BIT": "64","MB_LEN_MAX": "16","NGROUPS_MAX": "65536","NL_ARGMAX": "4096","NL_LANGMAX": "2048","NL_MSGMAX": "2147483647","NL_NMAX": "2147483647","NL_SETMAX": "2147483647","NL_TEXTMAX": "2147483647","NSS_BUFLEN_GROUP": "1024","NSS_BUFLEN_PASSWD": "1024","NZERO": "20","OPEN_MAX": "1024","PAGESIZE": "4096","PAGE_SIZE": "4096","PASS_MAX": "8192","PTHREAD_DESTRUCTOR_ITERATIONS": "4","PTHREAD_KEYS_MAX": "1024","PTHREAD_STACK_MIN": "16384","PTHREAD_THREADS_MAX": "","SCHAR_MAX": "127","SCHAR_MIN": "-128","SHRT_MAX": "32767","SHRT_MIN": "-32768","SSIZE_MAX": "32767","TTY_NAME_MAX": "32","TZNAME_MAX": "6","UCHAR_MAX": "255","UINT_MAX": "4294967295","UIO_MAXIOV": "1024","ULONG_MAX": "18446744073709551615","USHRT_MAX": "65535","WORD_BIT": "32","_AVPHYS_PAGES": "18689","_NPROCESSORS_CONF": "1","_NPROCESSORS_ONLN": "1","_PHYS_PAGES": "254536","_POSIX_ARG_MAX": "2097152","_POSIX_ASYNCHRONOUS_IO": "200809","_POSIX_CHILD_MAX": "1024","_POSIX_FSYNC": "200809","_POSIX_JOB_CONTROL": "1","_POSIX_MAPPED_FILES": "200809","_POSIX_MEMLOCK": "200809","_POSIX_MEMLOCK_RANGE": "200809","_POSIX_MEMORY_PROTECTION": "200809","_POSIX_MESSAGE_PASSING": "200809","_POSIX_NGROUPS_MAX": "65536","_POSIX_OPEN_MAX": "1024","_POSIX_PII": "","_POSIX_PII_INTERNET": "","_POSIX_PII_INTERNET_DGRAM": "","_POSIX_PII_INTERNET_STREAM": "","_POSIX_PII_OSI": "","_POSIX_PII_OSI_CLTS": "","_POSIX_PII_OSI_COTS": "","_POSIX_PII_OSI_M": "","_POSIX_PII_SOCKET": "","_POSIX_PII_XTI": "","_POSIX_POLL": "","_POSIX_PRIORITIZED_IO": "200809","_POSIX_PRIORITY_SCHEDULING": "200809","_POSIX_REALTIME_SIGNALS": "200809","_POSIX_SAVED_IDS": "1","_POSIX_SELECT": "","_POSIX_SEMAPHORES": "200809","_POSIX_SHARED_MEMORY_OBJECTS": "200809","_POSIX_SSIZE_MAX": "32767","_POSIX_STREAM_MAX": "16","_POSIX_SYNCHRONIZED_IO": "200809","_POSIX_THREADS": "200809","_POSIX_THREAD_ATTR_STACKADDR": "200809","_POSIX_THREAD_ATTR_STACKSIZE": "200809","_POSIX_THREAD_PRIORITY_SCHEDULING": "200809","_POSIX_THREAD_PRIO_INHERIT": "200809","_POSIX_THREAD_PRIO_PROTECT": "200809","_POSIX_THREAD_ROBUST_PRIO_INHERIT": "","_POSIX_THREAD_ROBUST_PRIO_PROTECT": "","_POSIX_THREAD_PROCESS_SHARED": "200809","_POSIX_THREAD_SAFE_FUNCTIONS": "200809","_POSIX_TIMERS": "200809","TIMER_MAX": "","_POSIX_TZNAME_MAX": "6","_POSIX_VERSION": "200809","_T_IOV_MAX": "","_XOPEN_CRYPT": "1","_XOPEN_ENH_I18N": "1","_XOPEN_LEGACY": "1","_XOPEN_REALTIME": "1","_XOPEN_REALTIME_THREADS": "1","_XOPEN_SHM": "1","_XOPEN_UNIX": "1","_XOPEN_VERSION": "700","_XOPEN_XCU_VERSION": "4","_XOPEN_XPG2": "1","_XOPEN_XPG3": "1","_XOPEN_XPG4": "1","BC_BASE_MAX": "99","BC_DIM_MAX": "2048","BC_SCALE_MAX": "99","BC_STRING_MAX": "1000","CHARCLASS_NAME_MAX": "2048","COLL_WEIGHTS_MAX": "255","EQUIV_CLASS_MAX": "","EXPR_NEST_MAX": "32","LINE_MAX": "2048","POSIX2_BC_BASE_MAX": "99","POSIX2_BC_DIM_MAX": "2048","POSIX2_BC_SCALE_MAX": "99","POSIX2_BC_STRING_MAX": "1000","POSIX2_CHAR_TERM": "200809","POSIX2_COLL_WEIGHTS_MAX": "255","POSIX2_C_BIND": "200809","POSIX2_C_DEV": "200809","POSIX2_C_VERSION": "","POSIX2_EXPR_NEST_MAX": "32","POSIX2_FORT_DEV": "","POSIX2_FORT_RUN": "","_POSIX2_LINE_MAX": "2048","POSIX2_LINE_MAX": "2048","POSIX2_LOCALEDEF": "200809","POSIX2_RE_DUP_MAX": "32767","POSIX2_SW_DEV": "200809","POSIX2_UPE": "","POSIX2_VERSION": "200809","RE_DUP_MAX": "32767","PATH": "/bin:/usr/bin","CS_PATH": "/bin:/usr/bin","LFS_CFLAGS": "","LFS_LDFLAGS": "","LFS_LIBS": "","LFS_LINTFLAGS": "","LFS64_CFLAGS": "-D_LARGEFILE64_SOURCE","LFS64_LDFLAGS": "","LFS64_LIBS": "","LFS64_LINTFLAGS": "-D_LARGEFILE64_SOURCE","_XBS5_WIDTH_RESTRICTED_ENVS": "XBS5_LP64_OFF64","XBS5_WIDTH_RESTRICTED_ENVS": "XBS5_LP64_OFF64","_XBS5_ILP32_OFF32": "","XBS5_ILP32_OFF32_CFLAGS": "","XBS5_ILP32_OFF32_LDFLAGS": "","XBS5_ILP32_OFF32_LIBS": "","XBS5_ILP32_OFF32_LINTFLAGS": "","_XBS5_ILP32_OFFBIG": "","XBS5_ILP32_OFFBIG_CFLAGS": "","XBS5_ILP32_OFFBIG_LDFLAGS": "","XBS5_ILP32_OFFBIG_LIBS": "","XBS5_ILP32_OFFBIG_LINTFLAGS": "","_XBS5_LP64_OFF64": "1","XBS5_LP64_OFF64_CFLAGS": "-m64","XBS5_LP64_OFF64_LDFLAGS": "-m64","XBS5_LP64_OFF64_LIBS": "","XBS5_LP64_OFF64_LINTFLAGS": "","_XBS5_LPBIG_OFFBIG": "","XBS5_LPBIG_OFFBIG_CFLAGS": "","XBS5_LPBIG_OFFBIG_LDFLAGS": "","XBS5_LPBIG_OFFBIG_LIBS": "","XBS5_LPBIG_OFFBIG_LINTFLAGS": "","_POSIX_V6_ILP32_OFF32": "","POSIX_V6_ILP32_OFF32_CFLAGS": "","POSIX_V6_ILP32_OFF32_LDFLAGS": "","POSIX_V6_ILP32_OFF32_LIBS": "","POSIX_V6_ILP32_OFF32_LINTFLAGS": "","_POSIX_V6_WIDTH_RESTRICTED_ENVS": "POSIX_V6_LP64_OFF64","POSIX_V6_WIDTH_RESTRICTED_ENVS": "POSIX_V6_LP64_OFF64","_POSIX_V6_ILP32_OFFBIG": "","POSIX_V6_ILP32_OFFBIG_CFLAGS": "","POSIX_V6_ILP32_OFFBIG_LDFLAGS": "","POSIX_V6_ILP32_OFFBIG_LIBS": "","POSIX_V6_ILP32_OFFBIG_LINTFLAGS": "","_POSIX_V6_LP64_OFF64": "1","POSIX_V6_LP64_OFF64_CFLAGS": "-m64","POSIX_V6_LP64_OFF64_LDFLAGS": "-m64","POSIX_V6_LP64_OFF64_LIBS": "","POSIX_V6_LP64_OFF64_LINTFLAGS": "","_POSIX_V6_LPBIG_OFFBIG": "","POSIX_V6_LPBIG_OFFBIG_CFLAGS": "","POSIX_V6_LPBIG_OFFBIG_LDFLAGS": "","POSIX_V6_LPBIG_OFFBIG_LIBS": "","POSIX_V6_LPBIG_OFFBIG_LINTFLAGS": "","_POSIX_V7_ILP32_OFF32": "","POSIX_V7_ILP32_OFF32_CFLAGS": "","POSIX_V7_ILP32_OFF32_LDFLAGS": "","POSIX_V7_ILP32_OFF32_LIBS": "","POSIX_V7_ILP32_OFF32_LINTFLAGS": "","_POSIX_V7_WIDTH_RESTRICTED_ENVS": "POSIX_V7_LP64_OFF64","POSIX_V7_WIDTH_RESTRICTED_ENVS": "POSIX_V7_LP64_OFF64","_POSIX_V7_ILP32_OFFBIG": "","POSIX_V7_ILP32_OFFBIG_CFLAGS": "","POSIX_V7_ILP32_OFFBIG_LDFLAGS": "","POSIX_V7_ILP32_OFFBIG_LIBS": "","POSIX_V7_ILP32_OFFBIG_LINTFLAGS": "","_POSIX_V7_LP64_OFF64": "1","POSIX_V7_LP64_OFF64_CFLAGS": "-m64","POSIX_V7_LP64_OFF64_LDFLAGS": "-m64","POSIX_V7_LP64_OFF64_LIBS": "","POSIX_V7_LP64_OFF64_LINTFLAGS": "","_POSIX_V7_LPBIG_OFFBIG": "","POSIX_V7_LPBIG_OFFBIG_CFLAGS": "","POSIX_V7_LPBIG_OFFBIG_LDFLAGS": "","POSIX_V7_LPBIG_OFFBIG_LIBS": "","POSIX_V7_LPBIG_OFFBIG_LINTFLAGS": "","_POSIX_ADVISORY_INFO": "200809","_POSIX_BARRIERS": "200809","_POSIX_BASE": "","_POSIX_C_LANG_SUPPORT": "","_POSIX_C_LANG_SUPPORT_R": "","_POSIX_CLOCK_SELECTION": "200809","_POSIX_CPUTIME": "200809","_POSIX_THREAD_CPUTIME": "200809","_POSIX_DEVICE_SPECIFIC": "","_POSIX_DEVICE_SPECIFIC_R": "","_POSIX_FD_MGMT": "","_POSIX_FIFO": "","_POSIX_PIPE": "","_POSIX_FILE_ATTRIBUTES": "","_POSIX_FILE_LOCKING": "","_POSIX_FILE_SYSTEM": "","_POSIX_MONOTONIC_CLOCK": "200809","_POSIX_MULTI_PROCESS": "","_POSIX_SINGLE_PROCESS": "","_POSIX_NETWORKING": "","_POSIX_READER_WRITER_LOCKS": "200809","_POSIX_SPIN_LOCKS": "200809","_POSIX_REGEXP": "1","_REGEX_VERSION": "","_POSIX_SHELL": "1","_POSIX_SIGNALS": "","_POSIX_SPAWN": "200809","_POSIX_SPORADIC_SERVER": "","_POSIX_THREAD_SPORADIC_SERVER": "","_POSIX_SYSTEM_DATABASE": "","_POSIX_SYSTEM_DATABASE_R": "","_POSIX_TIMEOUTS": "200809","_POSIX_TYPED_MEMORY_OBJECTS": "","_POSIX_USER_GROUPS": "","_POSIX_USER_GROUPS_R": "","POSIX2_PBS": "","POSIX2_PBS_ACCOUNTING": "","POSIX2_PBS_LOCATE": "","POSIX2_PBS_TRACK": "","POSIX2_PBS_MESSAGE": "","SYMLOOP_MAX": "","STREAM_MAX": "16","AIO_LISTIO_MAX": "","AIO_MAX": "","AIO_PRIO_DELTA_MAX": "20","DELAYTIMER_MAX": "2147483647","HOST_NAME_MAX": "64","LOGIN_NAME_MAX": "256","MQ_OPEN_MAX": "","MQ_PRIO_MAX": "32768","_POSIX_DEVICE_IO": "","_POSIX_TRACE": "","_POSIX_TRACE_EVENT_FILTER": "","_POSIX_TRACE_INHERIT": "","_POSIX_TRACE_LOG": "","RTSIG_MAX": "32","SEM_NSEMS_MAX": "","SEM_VALUE_MAX": "2147483647","SIGQUEUE_MAX": "3921","FILESIZEBITS": "64","POSIX_ALLOC_SIZE_MIN": "4096","POSIX_REC_INCR_XFER_SIZE": "","POSIX_REC_MAX_XFER_SIZE": "","POSIX_REC_MIN_XFER_SIZE": "4096","POSIX_REC_XFER_ALIGN": "4096","SYMLINK_MAX": "","GNU_LIBC_VERSION": "glibc","GNU_LIBPTHREAD_VERSION": "NPTL","POSIX2_SYMLINKS": "1","LEVEL1_ICACHE_SIZE": "32768","LEVEL1_ICACHE_ASSOC": "8","LEVEL1_ICACHE_LINESIZE": "64","LEVEL1_DCACHE_SIZE": "32768","LEVEL1_DCACHE_ASSOC": "8","LEVEL1_DCACHE_LINESIZE": "64","LEVEL2_CACHE_SIZE": "2097152","LEVEL2_CACHE_ASSOC": "8","LEVEL2_CACHE_LINESIZE": "64","LEVEL3_CACHE_SIZE": "0","LEVEL3_CACHE_ASSOC": "0","LEVEL3_CACHE_LINESIZE": "0","LEVEL4_CACHE_SIZE": "0","LEVEL4_CACHE_ASSOC": "0","LEVEL4_CACHE_LINESIZE": "0","IPV6": "200809","RAW_SOCKETS": "200809",}
        if self.args[0] in getconf_dict:
            self.honeypot.writeln(getconf_dict[self.args[0]])
        else:
            self.honeypot.writeln("")

commands['/usr/bin/getconf'] = command_getconf

# vim: set sw=4 et:
