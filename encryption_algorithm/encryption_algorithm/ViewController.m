//
//  ViewController.m
//  encryption_algorithm
//
//  Created by xinxi on 2021/6/17.
//

#import "ViewController.h"
#import "EncryptionTools.h"
#import "TokenInfo.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
}


- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    TokenInfo * user = [[TokenInfo alloc] init];
    if ([user isVipWithAccount:@"live4iPhone"]) {
        
       NSString * str = [[EncryptionToolsClass sharedEncryptionTools] encryptString:@"some message want to encrypted" keyString:nil iv:nil];
        NSLog(@"是VIP");

        [user sendWithUserInfo:str];
    }else{
        NSLog(@"不是VIP");
    }
}



@end
