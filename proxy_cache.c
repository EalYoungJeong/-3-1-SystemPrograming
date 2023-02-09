///////////////////////////////////////////////////////////////////////
// File Name		: proxy_cache.c		             	     //
// Date			: 2021/6/1			             //
// Os 			: Ubuntu 16.04 LTS 64bits	   	     //
// Author 		: Jeong Eal Young		             //
// Student ID		: 2016722033				     //
// ----------------------------------------------------------------- //
// Title : System Programing Assignment #3-1			     //
// Description : This assignment is to add thread t Assignment3-1.   //
// That is ,add a thread that writes logs in the critical section of //
// Assignmenet3-1. In the terminal, it prints not only the previously//
// implemented message, but alseo the critical section access part   //
// outputs about TID information.			             //
///////////////////////////////////////////////////////////////////////
// char *sha1_hash(char *input_url, char *hashed_url)                //
// ================================================================= //
// Input : char *input_url : Input original  URL by user	     //
//         char *hashed_url : hashed URL converted to hexademica     //
// Output : hashed_url : hashed URL converted to hexademical with    //
//                       SHA1, strcpy function                       //
// Purpose : convert input url to hash url and make it char * type   //
///////////////////////////////////////////////////////////////////////
// char *getHomeDir(char* home)					     //
// ================================================================= //
// Input : char* home : array that hold path of home directory	     //
// Output : char* home : array that hold path of home directory      //
// Purpose : get path of home directory	and make cache in home       //
//           directory						     //
///////////////////////////////////////////////////////////////////////
// int mkdir(const char *pathname, mode_t mode)			     //
// ================================================================= //
// Input : const char *pathname : path and name of directory	     //
//         mode_t mode : access permission of directory              //
// Output : -l : make directory error				     //
//          or : make directory success                              //
// Purpose : make directory where user wants			     //
///////////////////////////////////////////////////////////////////////
// DIR * opendir(const char * pathname)				     //
// ================================================================= //
// Input : const char * path : path and name of directory            //
//                             to open 				     //
// Output : DIR type pointer : indicates opened directory            //
// Purpose : open directory to get information			     //
//           NULL : on error		  			     //
///////////////////////////////////////////////////////////////////////
// struct dirent *readdir(DIR *dp)                                   //
// ================================================================= //
// Input : DIR *dp : directory pointer to read                       //
// Output : struct dirent : pointer represent next directory         //
//          NULL : on error or end of the directory		     //
// Purpose : search directories in directory  			     //
///////////////////////////////////////////////////////////////////////
// void closedir(DIR *dp)					     //
// ================================================================= //
// Input : DIR *dp : directory pointer to close 		     //
// Purpose : close directory 					     //
///////////////////////////////////////////////////////////////////////
// int open(const char *FILENAME, int FLAGS[, mode_t MODE])	     //
// ================================================================= //
// Input : const char *FILENAME : name of file including path        //
//        int FLAGS : option about file open e.g. O_RDONLY, O_WRONLY //
//                    O_CREAT, O_TRUNC, O_EXCL                       //
//         [mode_t MODE] : file permission when using O_CREAT option //
///Output : int 0< : file descriptor				     //
//              -1 : failure                                         //
// Purpose : create or open file                                     //
///////////////////////////////////////////////////////////////////////
// ssize_t write(int fd, const void *buf, size_t n)                  //
// ================================================================= //
// Input : int fd : file descriptor                                  //
//         void *buf : buffer with contents to be written to the file//
//         size_t n : number of bytes to write 		 	     //
// Output : ssize_t : number of bytes written                        //
//               -1 : failure					     //
// Purpose : write information in txt file or sending data to file   //
///////////////////////////////////////////////////////////////////////
// ssize_t read(int filedes, void *buf, size_t nbytes)		     //
// ================================================================= //
// Input : int filedes : file descriptor to receive data	     //
// 	   void *buf : buffer to save received data		     //
// 	   size_t nbytes : maximum of bytes to receive	   	     //
// Output : number of bytes to receive				     //
// Purpose : read information from another process		     //
///////////////////////////////////////////////////////////////////////
// pid_t fork(void)						     //
// ================================================================= //
// Output : pid_t Child process 0 : return 0 in child process        //
//              parent process : process ID of the new child         //
//              Error : -1  					     //
// Purpose : make new childe process that has copy of the parent's   //
//           data and stack 					     //
///////////////////////////////////////////////////////////////////////
// pid_t wait(int *statloc)                                          //
// ================================================================= //
// Input : int *statloc : has status of ended program		     //
// Output : process ID : process ID to wait                          //
//                  -1 : error                                       //
// Purpose : wait till child process ends			     //
///////////////////////////////////////////////////////////////////////
// int bind(int sockfd, const struct sockaddr *myaddr, socklen_t len)//
// ================================================================= //
// Input : int sockfd : return of calling socket function, socket no //
// 	   const struct sockaddr : server's onw socket address	     //
//                                 structure pointer		     //
//         socklen_t addrlen : size of myaddr structure		     //
// Output : 0 : OK						     //
//         -1 : error 						     //
// Purpose : binding socket and sockaddr_in structure		     //
//           assign ip, port num in structure to use generated socket//
///////////////////////////////////////////////////////////////////////
// int listen(int sockfd, int backlog)				     //
// ================================================================= //
// Input : int sockfd : return of calling socket function, socket no //
//         int backlog : the length of waiting queue	             //
// Output : 0 : OK						     //
//         -1 : error 						     //
// Purpose : When a connection request comes from client, it is put  //
//           in the waiting queue				     //
///////////////////////////////////////////////////////////////////////
// int accept(int sockfd, struct sockaddr *cliaddr, socklen_t *len)  //
// ================================================================= //
// Input : int sockfd : return of calling socket function, socket no //
//         struct sockaddr *cliaddr : socket structure of the client //
//				      requesting the connection      //
//         socklen_t *addrlen : size of cliaddr structure	     //
// Output : nonnegative descriptor : OK				     //
//          -1 : error					   	     //
// Purpose : Server accept client's connection			     //
///////////////////////////////////////////////////////////////////////
// int close(int filedes)			 		     //
// ================================================================= //
// Input : int filedes : file descriptor 			     //
// Output : 0 : OK						     //
//         -1 : error						     //
// Purpose : close file descriptor 				     //
///////////////////////////////////////////////////////////////////////
// unsigned long int htonl(unsigned long int hostlong)	    	     //
// ================================================================= //
// Input : unsigned long int hostlong : IP address 	    	     //
// Output : IP address to network byte order			     //
// Purpose : Unify network byte order 			             //
///////////////////////////////////////////////////////////////////////
// unsigned short int htons(unsigned short int hostshort)	     //
// ================================================================= //
// Input : unsigned short int hostshort : port number 		     //
// Output : port number to network byte order			     //
// Purpose : Unify network byte order 				     //
///////////////////////////////////////////////////////////////////////
// char* inet_ntoa(struct in_addr in);				     //
// ================================================================= //
// Input : struct in_addr in : Internet host address 		     //
// Output : dotted-decimal string				     //
//          NULL : error					     //
// Purpose : Converts IPv4based network addresses into dotted decimal//
// form simplification						     //
///////////////////////////////////////////////////////////////////////
// struct hostent *gethostbyname(const char *name)		     //
// ================================================================= //
// Input : const char* name : host name				     //
// Output : hostent structure : OK				     //
//          NULL : error					     //
// Purpose : to get IP adrress from URL				     //
///////////////////////////////////////////////////////////////////////
// void (*signal(int signo, void (*func)(int)))(int)		     //
// ================================================================= //
// Input : signo : name of signal				     //
//        void (*func)(int) : signal handler			     //
// Output : previous disposition of signal : OK			     //
//          SIG_ERR : error					     //
// Purpose : to handle signal					     //
///////////////////////////////////////////////////////////////////////
// unsigned int alarm(unsigned int seconds)			     //
// ================================================================= //
// Input : unsigned int seconds : after seconds send SIGALRM to      //
//				  process			     //
// Output : remain seconds till previous alarm send signal           //
// Purpose : alarm						     //
///////////////////////////////////////////////////////////////////////
// int semget(key_t key, int nsems, int flag)			     //
// ================================================================= //
// Input : key_t key : semaphore key				     //
//         int nesmes : the number of semaphores in the set	     //
//         int flag : IPC_CREAT, IPC_EXCL			     //
// Output : semaphore set identifier 			             //
// Purpose : create semaphore           			     //
///////////////////////////////////////////////////////////////////////
// int semctl(int semid, int semnum, int cmd, union semun arg)	     //
// ================================================================= //
// Input : int semid : Semaphore ID from semget	 	  	     //
//         int semnum : member number of Semaphore 	  	     //
//         int cmd : command to performance			     //
// Output : 0 : success						     //
//	   -1 : fail						     //
// Purpose : control semaphore					     //
///////////////////////////////////////////////////////////////////////
// int semop(int sem_id, struct sembuf *ops, unsigned nsops)         //
// ================================================================= //
// Input : int sem_id : semaphore ID from semget		     //
//         struct sembuf *ops : pointer specifying the operation to  //
//                              be performed on the semaphore        //
//         unsigned nsops : number of operations                     //
// Output : 0 : success						     //
//         -1 : fail						     //
// Purpose : change the value of semaphore			     //
///////////////////////////////////////////////////////////////////////
// int pthread_create(pthread_t *thread, const pthread_atter_t * attr//
//                    void*(*start)(void*), void* arg)               //
// ================================================================= //
// Input : pthread_t *thread : Thread ID			     //
//         const pthread_attr_t *attr : attribution of thread        //
//         void*(*start)(void*) : function call and start thread     //
//         void* arg : parameter of start function 		     //
// Output : 0 : success / else : error				     //
// Purpose : create thread					     //
///////////////////////////////////////////////////////////////////////
// int pthread_join(pthread_t thread, void** value_ptr)		     //
// ================================================================= //
// Input : pthread_t thread : identifier of thread to wait	     //
//         void** value_ptr : space that save end codes of thread    //
// Output : 0 : success / else : error				     //
// Purpose : end thread tasking and return memory resource 	     //
///////////////////////////////////////////////////////////////////////
#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/wait.h>
#include<sys/stat.h>
#include<openssl/sha.h>
#include<dirent.h>
#include<pwd.h>
#include<fcntl.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<netdb.h>
#include<signal.h>
#include<time.h>
#include<sys/sem.h>
#include<pthread.h>
#define BUFFSIZE	1024
#define PORTNO		4000
#define h_addr		h_addr_list[0]

int sub_process;
long int starttime;
time_t now;
char* sha1_hash(char* input_url, char* hashed_url)// make hashed url from input url
{
	unsigned char hashed_160bits[20];
	char hashed_hex[41];
	int i;

	SHA1(input_url, strlen(input_url), hashed_160bits);
	for (i = 0; i < sizeof(hashed_160bits); i++)
		sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);
	strcpy(hashed_url, hashed_hex);
	return hashed_url;
}
char* getHomeDir(char* home)//get Home directory path
{
	struct passwd* usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);
	return home;
}
static void handler()//handler that check child process is done
{
	pid_t pid;
	int status;
	while((pid = waitpid(-1, &status, WNOHANG))>0);
	//printf("Child process died\n");
}
void sig_int(int signo)//interrupt signal handle function
{
	char log_path[BUFFSIZE] = {0,};
	char logfile_path[BUFFSIZE] = {0,};
	char terminated[BUFFSIZE] = {0,};
	strcat(getHomeDir(log_path), "/logfile");//get logfile directory path
	strcpy(logfile_path, log_path);
	strcat(logfile_path, "/logfile.txt");
	int log_write = open(logfile_path, O_CREAT | O_APPEND | O_WRONLY, 0777);//make logfile.txt file
	sprintf(terminated, "**SERVER** [Terminated] run time : %ld sec, #sub process: %d\n", time(&now)-starttime, sub_process);
	write(log_write, terminated, strlen(terminated));
	close(log_write);
	//printf("%ld	%d\n", time(&now)-starttime, sub_process);
	printf("interrupt\n");
	exit(0);
}
char *getIPAddr(char * addr)//url -> IP address
{
	struct hostent* hent;
	char* haddr;
	int len = strlen(addr);
	if((hent = (struct hostent*)gethostbyname(addr))!=NULL)
		haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
	else printf("%d \n", h_errno);
	return haddr;
}
void sig_alarm(int signo)//alarm signal handle function
{
	printf("10 seconds over\n");
	printf("No response!!!\n");
	exit(0);
}



void p(int semid)//wait to use semaphore
{
	struct sembuf pbuf;
	pbuf.sem_num = 0;
	pbuf.sem_op = -1;
	pbuf.sem_flg = SEM_UNDO;
	if((semop(semid, &pbuf, 1))==-1)
	{
		perror("p : semop failed");
		exit(1);
	}
}

void v(int semid)//release semaphore
{
	struct sembuf vbuf;
	vbuf.sem_num = 0;
	vbuf.sem_op = 1;
	vbuf.sem_flg = SEM_UNDO;
	if((semop(semid, &vbuf, 1))==-1)
	{
		perror("v : semop failed");
		exit(1);
	}
}
void *thr_fn(void *buf)
{
	pthread_t itself;
	itself = pthread_self();
	printf("*PID# %d create the *TID# %u\n", getpid(), (unsigned int)itself);
}
int main()
{
	/////////variable for socket//////////////////////////
	struct sockaddr_in server_addr, client_addr;
	int socket_fd, client_fd;
	int len, len_out;
	int opt = 1;
	pid_t pid;//to use fork
	sub_process = 0;
	////////variable for time////////////////////////
	int starttimeflag = 1;
	struct tm* ltp;

	char cache_path[BUFFSIZE] = {0};
	char log_path[BUFFSIZE] = {0};
	char logfile_path[BUFFSIZE] = {0};
	int mResult;
	int log_write;
	///////variable for thread///////////////////////
	void *tret;
	pthread_t tid;	
	int err;
	char thr_buf[BUFFSIZE] = {0};	

	int semid;
	union semun
	{
		int val;
		struct semid_ds *buf;
		unsigned short int *array;
	} arg;
	
	if(signal(SIGALRM, sig_alarm)==SIG_ERR)//alarm signal
		printf("signal error\n");
	if(signal(SIGCHLD, handler)==SIG_ERR)//alarm signal
		printf("signal error\n");
	
	if(signal(SIGINT, sig_int)==SIG_ERR) //interrupt signal
	{
		printf("signal error\n");
		exit(0);
	}
	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)//IPv4, TCp type
	{
		printf("Server : Can't open stream socket\n");
		return 0;
	}
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	//////////////binding socket///////////////////////////////
	bzero((char*)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(PORTNO);
	
	//////////////assign socket address into socket file descriptor = binding////////////
	if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("Server : Can't bind local address\n");
		return 0;
	}
	listen(socket_fd, 5);//manage the waiting queue for client connection
	strcat(getHomeDir(cache_path), "/cache");//get cache directory path
	strcat(getHomeDir(log_path), "/logfile");//get logfile directory path
	mResult = mkdir(cache_path, 0777);//make cache directory
	if(mResult == -1)
	{
		if(errno == ENOENT)
		{
			printf("make directory error\n");
			close(client_fd);
			exit(-1);
		}
	}
	mResult = mkdir(log_path, 0777);//make logfile directory
	if(mResult == -1)
	{
		if(errno == ENOENT)
		{
			printf("make directory error\n");
			close(client_fd);
			exit(-1);
		}
	}
	else
	{
		strcpy(logfile_path, log_path);
		strcat(logfile_path, "/logfile.txt");
		log_write = open(logfile_path, O_CREAT | O_APPEND | O_WRONLY, 0777);//make logfile.txt file
		if(log_write == -1)
		{
			close(socket_fd);
			close(client_fd);
			exit(-1);
		}
	}
	while(1)
	{
		char buf[BUFFSIZE];//request message for client
		char response_header[BUFFSIZE] = {0};//
		char temp[BUFFSIZE] = {0};//to get url
		char method[BUFFSIZE] = {0};//to get "GET"
		char HITorMISS[10] = {0};//Send Hit or Miss to client
		char input_url[BUFFSIZE] = {0};//Input_url from client
		char hashed_url[BUFFSIZE] = {0};//hashed url
		char *tok = NULL;//to use strtok function
		
		/////////////////////variable for Assignment#1/////////////////
		
		char dir_path[BUFFSIZE] = {0};//directory in cache path
		char dir_name[BUFFSIZE] = {0};//name of directory
		char file_path[BUFFSIZE] = {0};//file in directory in cache path
		char com_dir_path[BUFFSIZE] = {0};//to compare input url with directory in cache
		char com_url[BUFFSIZE] = {0};//to compare input url with file in directory
		char time_string[BUFFSIZE] = {0};
		char hit1_string[BUFFSIZE] = {0};
		char hit2_string[BUFFSIZE] = {0};
		char miss_string[BUFFSIZE] = {0};
		
		int i;//index for loop
		int hit_flag;//determine hit or miss
		int statloc;
		
		DIR* pDir;//for checking directory in cache(pDir = cache)
		DIR* ppDir;//for checking file in directory(ppDir = directory)
		struct dirent* pFile;//for searching cache directories
		struct dirent* ppFile;//for searching directory
		

		umask(0);//give all permission to everyone
	
		
		struct in_addr inet_client_address;
		len = sizeof(client_addr);
		//accept client's connection, assign client socket address into client socket file descriptor
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);
		if(client_fd < 0)
		{
			printf("Server : accept failed\n");
			return 0;
		}
		inet_client_address.s_addr = client_addr.sin_addr.s_addr;
		if((semid = semget((key_t)PORTNO, 1, IPC_CREAT|0666))==-1)
		{
			perror("semget failed");
			exit(1);
		}
		arg.val = 1;
		if((semctl(semid, 0, SETVAL, arg)) == -1)
		{
			perror("semctl failed");
			exit(1);
		}
		pid = vfork();//make sub process to communication with web server
		if(pid == -1)
		{
			close(client_fd);
			close(socket_fd);
			return 0;
		}
		if(pid > 0) wait(&statloc);
		if(pid == 0)//in child process
		{
			
			printf("*PID# %d is waiting for the semaphore.\n", getpid());
			if(starttimeflag)
			{
				starttime = time(&now);
				starttimeflag = 0;
			}

			hit_flag = 0;//initialize hit flag
			//printf("[%s : %d] client was connected\n", inet_ntoa(inet_client_address), client_addr.sin_port);//print connect message

			read(client_fd, buf, BUFFSIZE);//read request message from client
			strcpy(temp, buf);
		
			///////////////////Parsing Request URL/////////////////
			tok = strtok(temp, " ");
			strcpy(method, tok);
			if(!strcmp(method, "GET"))
			{
				tok = strtok(NULL, " ");
				if(!strncmp(tok, "http://detect",13))
				{
					close(client_fd);
					exit(0);
				}
				strcpy(input_url, tok);
				//printf("%s\n", input_url);
			}
			
			else//don't make directory or files when request message is not GET
			{
				close(client_fd);
				exit(-1);
			}
			char url_temp[BUFFSIZE]={0};//delete http:// and last / character
			char url[BUFFSIZE]={0};
			strcpy(url_temp, &input_url[7]);
			if(url_temp[strlen(url_temp)-1] == '/')
				strncpy(url, url_temp, strlen(url_temp)-1);
			else strncpy(url, url_temp, strlen(url_temp));
			/////////////////end of Parsing Request URL

		
			//////Determine hit or miss and make directories//////////////
			
			
			strcpy(dir_path, cache_path);//make directory path
			sha1_hash(url, hashed_url);//make input url to hashed url
			pDir = opendir(cache_path);//open cache directory
			strncpy(dir_name, hashed_url, 3);//get directory name from hashed url
			time(&now);
			ltp = localtime(&now);
			sprintf(time_string, "-[%d/%02d/%02d, %02d:%02d:%02d]", ltp->tm_year + 1900, ltp->tm_mon + 1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);

			for(pFile = readdir(pDir); pFile; pFile = readdir(pDir))//Search cache directory
			{
				if(!strcmp(pFile->d_name, dir_name))//if dir_name is in cache
				{
					strcpy(com_dir_path, cache_path);
					strcat(com_dir_path, "/");
					strcat(com_dir_path, pFile->d_name);//make comparing directory path
					ppDir = opendir(com_dir_path);//open directory
					for(ppFile = readdir(ppDir);ppFile;ppFile=readdir(ppDir))
					{//search directory
						if(!strcmp(ppFile->d_name, &hashed_url[3]))
						{//if there is same named file
							hit_flag = 1;//hit flag on
							break;//escape loop
						}
					}
					closedir(ppDir);//close directory
					memset(com_dir_path, 0, sizeof(com_dir_path));//initialize directory path
				}
				if(hit_flag) break;//if hit flag on, escape loop
			}
			closedir(pDir);
			
			//printf("sub process : %d\n", sub_process);
			if(hit_flag)//if hit
			{
				p(semid);//get semaphore
				sub_process++;
				printf("*PID# %d is in the critical zone.\n", getpid());
				char file_data_buf[BUFFSIZE]={0};
				char file_data[BUFFSIZE]={0};
				char response_header[BUFFSIZE]={0};
				strcat(dir_path, "/");
				strcat(dir_path, dir_name);//get directory path
				strcpy(file_path, dir_path);
				strcat(file_path, "/");
				strcat(file_path, &hashed_url[3]);//get file path
				FILE* fp = fopen(file_path, "r");
				while(!feof(fp))//get data saved in file 
				{
					fgets(file_data_buf, BUFFSIZE, fp);
					strcat(file_data, file_data_buf);
				}
				//printf("HIT\n");
				sprintf(response_header, "HTTP/1.1 200 OK\r\n"
						"Server:2021 simple web server\r\n"
						"Content-length:%lu\r\n"
						"Content-type:text/html\r\n\r\n", strlen(file_data));
				write(client_fd, response_header, strlen(response_header));//send response header to client
				write(client_fd, file_data, strlen(file_data));//send file data to client
				close(client_fd);//close client socket

				//////////make thread and write log///////////////
				err = pthread_create(&tid, NULL, thr_fn, (void*)thr_buf);
				
				if(err !=0)
				{
					printf("pthread_create() error\n");
					return 0;
				}
				log_write = open(logfile_path, O_CREAT | O_WRONLY | O_APPEND, 0777);
				if(log_write == -1) printf("hit open log fail\n");
				sprintf(hit1_string, "[Hit]%s/%s%s\n", dir_name, &hashed_url[3], time_string);
				sprintf(hit2_string, "[Hit]%s\n", input_url);
				write(log_write, hit1_string, strlen(hit1_string));
				write(log_write, hit2_string, strlen(hit2_string));
				close(log_write);
				printf("*TID# %u is exited.\n", (unsigned int)tid);
				pthread_join(tid, &tret);
				////////////end thread/////////////////////////
				sleep(5);
				printf("*PID# %d exited the critical zone.\n", getpid());
				v(semid);//release semaphore
				exit(0);//end process
			}
			else//if miss
			{	
				p(semid);//get semaphore
				printf("*PID# %d is in the critical zone.\n", getpid());
				sub_process++;
				int count = 0;
				char* IPAddr;
			
				//printf("%s\n", url);
				//////////make thread and write log///////////////
				err = pthread_create(&tid, NULL, thr_fn, (void*)thr_buf);
				//printf("now thread : %u\n", (unsigned int)tid);
				if(err !=0)
				{
					printf("pthread_create() error\n");
					return 0;
				}
				log_write = open(logfile_path, O_CREAT | O_WRONLY | O_APPEND, 0777);
				sprintf(miss_string, "[Miss]%s%s\n", url, time_string);
				write(log_write, miss_string, strlen(miss_string));
				close(log_write);
				printf("*TID# %u is exited.\n", (unsigned int)tid);
				pthread_join(tid, &tret);
				//////////end thread/////////////////////////
				IPAddr = getIPAddr(url);//url -> IP address
				
				//printf("%s\n", IPAddr);
				int web_fd, len_web;
				struct sockaddr_in web_addr;
				bzero((char*)&web_addr, sizeof(web_addr));
				//////make Web server socket///////////////////////
				if((web_fd = socket(PF_INET, SOCK_STREAM, 0))<0)
				{
					printf("Server : Can't open stream socket\n");
					return 0;
				}
				/////////input IP information into web address structure
				web_addr.sin_family = AF_INET;
				web_addr.sin_addr.s_addr = inet_addr(IPAddr);
				web_addr.sin_port = htons(80);
				////////connect to Web Server////////////////////////
				if(connect(web_fd, (struct sockaddr*)&web_addr, sizeof(web_addr))<0)
				{
					//printf("Server : Can't connect web server\n");
					return 0;
				}
				//else printf("Server : connect web server success\n");

				//////////send request to Web serber/////////
				char requestToWeb[BUFFSIZE];//request message from Web browser
				char responseFromWeb[BUFFSIZE];//respone message from Web server
				bzero(requestToWeb, sizeof(requestToWeb));
				bzero(responseFromWeb, sizeof(responseFromWeb));
				strcpy(requestToWeb, buf);
				/*while(count<10)//to disconnect network
				{
					//printf("%d seconds after alarm start!\n", 10-(count++));
					sleep(1);
				}*/
				write(web_fd, requestToWeb, strlen(requestToWeb));//send request to Web browser
				//printf("write request\n");
				len = read(web_fd, responseFromWeb, BUFFSIZE);//receive response from Web Server
				if(len == 0) printf("Read failed\n");
				write(client_fd, responseFromWeb, len);//send reponse to Web browser
				
				/////////make directory and file///////////////////////
				/////////write response message to file////////////////
				strcat(dir_path, "/");
				strcat(dir_path, dir_name);//get directory path
				mResult = mkdir(dir_path, 0777);//make directory
				strcpy(file_path, dir_path);
				strcat(file_path, "/");
				strcat(file_path, &hashed_url[3]);//get file path
				open(file_path, O_RDONLY|O_CREAT|O_EXCL, 0777);//make file
				
				
				FILE* fp = fopen(file_path, "w");
				fprintf(fp, "%s", responseFromWeb);//write reponse message into file
				//printf("%s\n", responseFromWeb);
				fclose(fp);
				close(web_fd);
				close(client_fd);//close client socket
				sleep(5);
				printf("*PID# %d exited the critical zone.\n", getpid());
				v(semid);//release semaphore
				exit(0);//end process
			}
		}
	}
	close(socket_fd);//close server socket
	return 0;
}
