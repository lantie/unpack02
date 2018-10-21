# unpack02
upx静态脱壳机源码

# 说明
本代码是15pb的一个小项目，Upx静态脱壳机的源码，通过分析upx壳代码，我们可以完成这个项目。  
代码思路：  
① 读取文件到内存  
映射PE头到内存  
映射每一个区段到内存  
② 解密内存中的代码和数据  
计算src和dest  
调用解压缩函数  
③ 在内存中获取IAT，获取导入表相关信息,还原导入表  
找到原PE文件的导入表结构  
修复导入表结构、IAT  
④ dump内存  
修正区段、oep，保存文件  

# 广告
逆向最有趣的就是突破自己，如果你也想突破自己，来15PB吧，学习真正的信息安全技术! http://www.15pb.com.cn/
