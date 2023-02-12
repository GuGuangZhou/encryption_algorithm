//
//  TokenInfo.m
//  encryption_algorithm
//
//  Created by xinxi on 2021/6/17.
//

#import "TokenInfo.h"

@implementation TokenInfo

-(BOOL)isVipWithAccount:(NSString *)account{
    
    if ([account isEqualToString:@"hank"]) {
        return YES;
    }
    return NO;
    
}

//给服务器发敏感信息
-(void)sendWithUserInfo:(NSString *)info
{
    NSLog(@"发送的是:%@",info);
    
}

@end
