//
//  EncryptionTools.m
//  encryption_algorithm
//
//  Created by xinxi on 2021/6/10.
//

#import "EncryptionTools.h"
#import <dlfcn.h>

@interface EncryptionToolsClass()
@property (nonatomic, assign) int keySize;
@property (nonatomic, assign) int blockSize;
@end

@implementation EncryptionToolsClass

//采用^运算直接换算成结果.不会进入字符串常量区
#define STRING_ENCRYPT_KEY 0xAC
static NSString * AES_KEY(){
    unsigned char key[] = {
        (STRING_ENCRYPT_KEY ^ 'I'),
        (STRING_ENCRYPT_KEY ^ 'U'),
        (STRING_ENCRYPT_KEY ^ 'I'),
        (STRING_ENCRYPT_KEY ^ 'D'),
        (STRING_ENCRYPT_KEY ^ 'I'),
        (STRING_ENCRYPT_KEY ^ 'S'),
        (STRING_ENCRYPT_KEY ^ 'T'),
        (STRING_ENCRYPT_KEY ^ 'P'),
        (STRING_ENCRYPT_KEY ^ '#'),
        (STRING_ENCRYPT_KEY ^ '\0')
    };
    unsigned char * p = key;
    while (((*p) ^=  STRING_ENCRYPT_KEY) != '\0') p++;
    
   return [NSString stringWithUTF8String:(const char *)key];
}

+ (instancetype)sharedEncryptionTools {
    static EncryptionToolsClass *instance;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
        instance.algorithm = kCCAlgorithmAES;
    });
    
    return instance;
}

- (void)setAlgorithm:(uint32_t)algorithm {
    _algorithm = algorithm;
    switch (algorithm) {
        case kCCAlgorithmAES:
            self.keySize = kCCKeySizeAES128;
            self.blockSize = kCCBlockSizeAES128;
            break;
        case kCCAlgorithmDES:
            self.keySize = kCCKeySizeDES;
            self.blockSize = kCCBlockSizeDES;
            break;
        default:
            break;
    }
}

- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {

    keyString = AES_KEY();
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[self.keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:self.keySize];
    
    // 设置iv
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [data length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    // 开始加密
    size_t encryptedSize = 0;
    //加密解密都是它 -- CCCrypt
    //裁剪符号表，隐藏CCCrypt
    
    unsigned char str[] = {
        ('a' ^ 'C'),
        ('a' ^ 'C'),
        ('a' ^ 'C'),
        ('a' ^ 'r'),
        ('a' ^ 'y'),
        ('a' ^ 'p'),
        ('a' ^ 't'),
        ('a' ^ '\0')
    };
    unsigned char * p = str;
    while (((*p) ^= 'a') != '\0') p++;
    
    //句柄
    void * handle = dlopen("/usr/lib/system/libcommonCrypto.dylib",RTLD_LAZY);
    
    CCCryptorStatus (* CCCrypt_p)(
                            CCOperation op,         /* kCCEncrypt, etc. */
                            CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
                            CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
                            const void *key,
                            size_t keyLength,
                            const void *iv,         /* optional initialization vector */
                            const void *dataIn,     /* optional per op and alg */
                            size_t dataInLength,
                            void *dataOut,          /* data RETURNED here */
                            size_t dataOutAvailable,
                            size_t *dataOutMoved)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0)  = dlsym(handle, (const char *)str);
    
    if (!CCCrypt_p) {
        return nil;
    }
    
    CCCryptorStatus cryptStatus = CCCrypt_p(kCCEncrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 加密失败|状态编码: %d", cryptStatus);
    }
    
    return [result base64EncodedStringWithOptions:0];
}

- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {
    
    keyString = AES_KEY();
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[self.keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:self.keySize];
    
    // 设置iv
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
    size_t bufferSize = [data length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    // 开始解密
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 解密失败|状态编码: %d", cryptStatus);
    }
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

@end

