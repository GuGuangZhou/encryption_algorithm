//
//  TokenInfo.h
//  encryption_algorithm
//
//  Created by xinxi on 2021/6/17.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TokenInfo : NSObject

-(BOOL)isVipWithAccount:(NSString *)account;

//给服务器一些敏感信息
-(void)sendWithUserInfo:(NSString *)info;

@end

NS_ASSUME_NONNULL_END
