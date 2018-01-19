#ifndef URL_H  
#define URL_H  
  
#ifdef __cplusplus  
extern "C" {  
#endif  
  
int url_decode(char *str);  
char *url_encode(const char *s, int *new_length);  
  
#ifdef __cplusplus  
}  
#endif  
  
#endif /* URL_H */  
