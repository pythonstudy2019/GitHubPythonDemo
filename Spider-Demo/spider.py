#coding=utf-8
import requests,re,time

def get_title(Html):
    '''
    用re抽取网页Title
    '''
    compile_rule = r'<title>.*</title>'
    title_list = re.findall(compile_rule, Html)
    if title_list == []:
        title = ''
    else:
        title = title_list[0][7:-8]
    return title

kw={'wd':'长城'}
url="http://www.baidu.com/s?"
##url="https://shop.m.suning.com/allProduct/70864955.html?bottom=allprod&safp=f73ee1cf.MSFS_allProduct.13928077.2"
headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36",
         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip, deflate, br'
         }
##print(re.findall('(?<=\<title\>).+?(?=\<)', response.text, re.S))
i=0;
while(1):
    kw['wd']='长城 '+str(i);
    response = requests.get(url, params=kw, headers=headers)
    ##print(response.text)
    ret=get_title(response.text)
    print(" ret --- %s --- %d" %(ret, i))
    time.sleep(2)
    i=i+1
    print("sleep 2s ... ")
    assert i != 4, 'i is 4!'