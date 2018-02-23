#-*-coding:utf-8-*- #编码声明，不要忘记！
import requests
import json
import time
import mailhelper
import thread

mailto = ['17538006@qq.com','florashine@163.com',]
#mailto = ['17538006@qq.com',]

def fetchHdFax(yieldrate, days):
    print("HDFax thread up")
    records = {}
    index = 1
    while 1:
        try:
            page = requests.get('https://www.hdfax.com/financialproduct/secondaryMarket/list/%s?pageNum=%s&rateOrderBy=0&buyAmtOrderBy=0&productLimit=-1&productLimitOrderBy=1&buyAmtRange=-1'%(index, index))
            if page.status_code >= 300:
                print("request status error: "+page.status_code)
                index = 1
                continue
            productData = page.json()
            #print(productData)
            if productData['hasNextPage']:
                index = index+1
            else:
                index = 1
            time.sleep(0.5)
            productList = productData['productList']
            for v in productList:
                desc = '{0}, {1}, {2}'.format(v['productLimit'], v['investAmount'], v['expectedAnnualYieldRate'])
                if float(v['expectedAnnualYieldRate']) > yieldrate and v['productLimit'] < days:
                    if not v['productId'] in records:
                        print("hdfax - hit -- " + desc)
                        records[v['productId']] = v
                        mailhelper.sendmail(mailto, 'AJ理财通知', '恒大金服 -- {:.2f}% | {}天 | {:,}'.format(float(v['expectedAnnualYieldRate']), v['productLimit'], float(v['investAmount'])))
        except:
            index = 1


def main():
    thread.start_new_thread(fetchHdFax, (6.0, 40))
    while True:
        time.sleep(1)
        

main()
