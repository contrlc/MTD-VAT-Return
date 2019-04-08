'''
Created on 4 Nov 2018

@author: Steve Webster, Barnaby Park

    Copyright 2018, 2019 Dhryrock Technologies Limited
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
import requests
import sys
from optparse import OptionParser
from requests_oauthlib import OAuth2Session
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import WebDriverException
import platform
import json
import urllib
import ast
import psutil
from datetime import datetime
import time
import os
import re

VERSION = '1.0'

redirect_uri = "urn:ietf:wg:oauth:2.0:oob:auto"
authorization_url = 'https://test-api.service.hmrc.gov.uk/oauth/authorize'
token_url = 'https://test-api.service.hmrc.gov.uk/oauth/token'
api_url = "https://test-api.service.hmrc.gov.uk/organisations/vat/"

def get_mac_addresses(family):
    for snics in psutil.net_if_addrs().items():
        for snic in snics:
            if isinstance(snic, list):
                for snicaddr in snic:            
                    if snicaddr.family == family:
                        yield snicaddr.address

def readCredentialsData(filepathname, periodKey):
    # credentials text file is 3 lines long and contains the following credentials 
    if platform.system() == "Windows":            
        idx = filepathname.rfind("\\")
    else:
        idx = filepathname.rfind("/")        
    filename = "credentials.txt"
    dstpathname = filepathname[:idx+1] + filename
    # open file
    try:
        f= open(dstpathname,"r")
    except IOError as e:
        print ("file " + dstpathname + "I/O error({0}): {1}".format(e.errno, e.strerror))
        error = "ERROR: failed to open credentials file, error=" + e.strerror
        saveResult(filepathname, 400, periodKey, error, "", "", "")
        return "", "", ""
    else:
        # read client id and strip off any carrage return, line feed chars
        client_id = f.readline().strip("\n")
        # read client_secret
        client_secret = f.readline().strip("\n")
        #read server_token
        server_token = f.readline().strip("\n")
        # close credentials file
        f.close()
        return client_id, client_secret, server_token  
    
def fileReturn(periodKey, vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue, totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT, VATReg, access_token):
    # convert period key
    if periodKey == "Q1":
        period = "Q001"
    elif periodKey == "Q2":
        period = "Q002"
    elif periodKey == "Q3":
        period = "Q003"
    else:
        period = "Q004"    
    print(VATReg)
    args = "periodKey="+period+", vatDueSales="+vatDueSales+", vatDueAcquisitions="+vatDueAcquisitions+", totalVatDue="+totalVatDue+", vatReclaimedCurrPeriod="+vatReclaimedCurrPeriod+", netVatDue="+netVatDue+", totalValueSalesExVAT="+totalValueSalesExVAT+", totalValuePurchasesExVAT="+totalValuePurchasesExVAT+", totalValueGoodsSuppliedExVAT="+totalValueGoodsSuppliedExVAT+", totalAcquisitionsExVAT="+totalAcquisitionsExVAT+", VATReg="+VATReg
    print (args)
    
    post_data = {
      "periodKey": period,
      "vatDueSales": vatDueSales,
      "vatDueAcquisitions": vatDueAcquisitions,
      "totalVatDue": totalVatDue,
      "vatReclaimedCurrPeriod": vatReclaimedCurrPeriod,
      "netVatDue": netVatDue,
      "totalValueSalesExVAT": totalValueSalesExVAT,
      "totalValuePurchasesExVAT": totalValuePurchasesExVAT,
      "totalValueGoodsSuppliedExVAT": totalValueGoodsSuppliedExVAT,
      "totalAcquisitionsExVAT": totalAcquisitionsExVAT,
      "finalised": True}

    # get fraud prevention headers
    req = urllib.request.Request('http://icanhazip.com', data=None)  
    response = urllib.request.urlopen(req, timeout=5)  
    ipaddr = str(response.read())
    pub_ipaddr = ipaddr.strip('\n')
    # get user     
    userhome = os.path.expanduser('~')          
    # Gives username by splitting path based on OS
    os_user = "os=" + os.path.split(userhome)[-1]
    # get timezone info
    ts = time.time()
    utc_offset = (datetime.fromtimestamp(ts) - datetime.utcfromtimestamp(ts)).total_seconds()
    #convert second offset to mins:secs format
    mins = utc_offset / 60
    secs = utc_offset - (mins * 60)
    if utc_offset >= 0:
        utc_time = "UTC+%02u:%02u" % (mins, secs)
    else:
        utc_time = "UTC%02u:%02u" % (mins, secs)
    # get sw_version
    sw_version = "my-desktop-software="+VERSION
    #* get list of MAC addresses of available interfaces
    macs = list(get_mac_addresses(psutil.AF_LINK))
    # init final mac string
    mac = ""
    for i in macs:
        # replace any '-' with ':' and then convert to %3a format
        i = urllib.parse.quote(i.replace("-", ":"))
        # check for duplicate MAC addresses
        if mac.count(i):
            continue;
        # after first MAC address add spacer 
        if mac:
            mac = mac + ','
        # add MAC address to string
        mac = mac + i
    # add extra headers
    payload= {
        'Authorization': "Bearer "+access_token, 
        'Accept': 'application/vnd.hmrc.1.0+json', 
        'Content-Type': 'application/json',
        # fraud prevention headers
        'Gov-Client-Connection-Method': 'DESKTOP_APP_DIRECT',
        'Gov-Client-Public-IP': pub_ipaddr,
        'Gov-Client-Device-ID': os_user,
        'Gov-Client-Timezone': utc_time, 
        'Gov-Client-User-Agent': str(platform.system())+'/'+str(platform.release())+" (/)",
        'Gov-Vendor-Version': sw_version,
        'Gov-Client-MAC-Addresses': mac  
    }
    # send HTTP POST request
    url = api_url+str(VATReg)+"/returns"
    r = requests.post(url,
                      headers=payload,
                      data=json.dumps(post_data))

    print ("http status = " + str(r.status_code))
    return r.status_code, r.text

def access_token_request(auth, client_id, client_secret):
    post_data = {'grant_type': 'authorization_code',
                 'code': auth,
                 'client_id' : client_id,
                 'client_secret' : client_secret,
                 'redirect_uri': redirect_uri}
    response = requests.post(token_url,
                             data=post_data)
    token_json = response.json()
    return token_json, response.status_code

def authorization_request(uri, client_id):
    scope=[('write:vat'), ('read:vat')]
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(uri)
    # open web browser
    options = webdriver.ChromeOptions()
    if platform.system() == "Windows":            
        options.binary_location = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    else:
        options.binary_location = "/usr/bin/google-chrome"
    options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(chrome_options=options)
    driver.get(authorization_url)
    try:
        element = WebDriverWait(driver, 60).until(lambda x: 'Success code=' in driver.title or 'Denied error=' in driver.title)
        if element:
            auth_code = driver.title.split("Success code=", 1).pop()
        else:
            # close browser
            driver.quit()
            return "ERROR: Failed to get Authorisation code"
    except NoAlertPresentException:
        # close browser
        driver.quit()
        return "ERROR: Autorisation request timed out"
    except WebDriverException:
        # close browser
        driver.quit()
        return "ERROR: Browser was closed"
    except:
        # close browser
        driver.quit()
        return "ERROR: Autorisation request timed out"
        
    finally:
        # close browser
        driver.quit()

    print ("auth code = " + str(auth_code))
    # return auth code
    return auth_code

def saveResult(filepathname, status, periodKey, processingDate, paymentIndicator, formBundleNumber, chargeRefNumber):
    # create text file
    if platform.system() == "Windows":            
        idx = filepathname.rfind("\\")
    else:
        idx = filepathname.rfind("/")        
    filename = "filingResults.txt"
    dstpathname = filepathname[:idx+1] + filename
    #if old version of the file exists, deleteit
    if os.path.isfile(dstpathname):
        os.remove(dstpathname)
    # create new file
    f= open(dstpathname,"w+")
    line = str(status) + "\n"
    f.write(line)
    line = periodKey + "\n"
    f.write(line)
    line = processingDate + "\n"
    f.write(line)
    line = paymentIndicator + "\n"
    f.write(line)
    line = formBundleNumber + "\n"
    f.write(line)
    line = chargeRefNumber + "\n"
    f.write(line)
    f.close()

def main(argv):
    parser = OptionParser(usage="%prog [options] periodKey, vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue, totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT, VATReg filepathname\n", version="%prog " + VERSION)
    parser.add_option('-d', '--debug', dest='DEBUG', default=False, action='store_true', help='print information to help debug the script [default: %default]')

    opt, args = parser.parse_args(argv[1:])
    if len(args) != 12:
        parser.print_help()
        return "ERROR: invalid number of arguments=" + str(len(args))
    else:
        try:
            if len(args) > 11:
                filepathname = args[11]                
            if len(args) > 10:
                VATReg = args[10]
            if len(args) > 9:
                totalAcquisitionsExVAT = re.sub('\,', '', args[9])
                if totalAcquisitionsExVAT == "none":
                    totalAcquisitionsExVAT = "0.00"
            if len(args) > 8:
                totalValueGoodsSuppliedExVAT = re.sub('\,', '', args[8])
                if totalValueGoodsSuppliedExVAT == "none":
                    totalValueGoodsSuppliedExVAT = "0.00"
            if len(args) > 7:
                totalValuePurchasesExVAT = re.sub('\,', '', args[7])
                if totalValuePurchasesExVAT == "none":
                    totalValuePurchasesExVAT = "0.00"
            if len(args) > 6:
                totalValueSalesExVAT = re.sub('\,', '', args[6])
                if totalValueSalesExVAT == "none":
                    totalValueSalesExVAT = "0.00"
            if len(args) > 5:
                netVatDue = re.sub('\,', '', args[5])
                if netVatDue == "none":
                    netVatDue = "0.00"
            if len(args) > 4:
                vatReclaimedCurrPeriod = re.sub('\,', '', args[4])
                if vatReclaimedCurrPeriod == "none":
                    vatReclaimedCurrPeriod = "0.00"
            if len(args) > 3:
                totalVatDue = re.sub('\,', '', args[3])
                if totalVatDue == "none":
                    totalVatDue = "0.00"
            if len(args) > 2:
                vatDueAcquisitions = re.sub('\,', '', args[2])
                if vatDueAcquisitions == "none":
                    vatDueAcquisitions = "0.00"
            if len(args) > 1:
                vatDueSales = re.sub('\,', '', args[1])
                if vatDueSales == "none":
                    vatDueSales = "0.00"
            if len(args) > 0:
                periodKey = args[0]
        except:
            parser.print_help()
            return saveResult(filepathname, 400, "Q1", "ERROR: invalid number of arguments", "", "", "")
#    print_args = "periodKey="+periodKey+", vatDueSales="+vatDueSales+", vatDueAcquisitions="+vatDueAcquisitions+", totalVatDue="+totalVatDue+", vatReclaimedCurrPeriod="+vatReclaimedCurrPeriod+", netVatDue="+netVatDue+", totalValueSalesExVAT="+totalValueSalesExVAT+", totalValuePurchasesExVAT="+totalValuePurchasesExVAT+", totalValueGoodsSuppliedExVAT="+totalValueGoodsSuppliedExVAT+", totalAcquisitionsExVAT="+totalAcquisitionsExVAT+", VATReg="+VATReg+", filepathname=",filepathname
#    print (print_args)       
    filepathname = urllib.parse.unquote(filepathname)
    filepathname = filepathname.strip("file:")
    # get credential data
    client_id, client_secret, server_token = readCredentialsData(filepathname, periodKey)
    if not client_id:
        return
    #authorization request
    auth = authorization_request(authorization_url, client_id)
    # check authorisation was successful
    if auth.find("ERROR") != -1 or auth.find("Denied error") != -1:
        # exit returning error string
        return saveResult(filepathname, 400, auth, "", "", "", "")
    #get access token
    access_token, status_code = access_token_request(auth, client_id, client_secret)
    if status_code >= 400:
        desc = access_token[u'error_description']
        err = access_token[u'error']
        return saveResult(filepathname, status_code, desc, err, "", "", "")
#    print ('access token = ' + access_token[u'access_token'])
    access_token = access_token[u'access_token']
    #send VAT return
    status, text = fileReturn(periodKey, vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue, totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT, VATReg, access_token)
    # convert unicode string to dictionary
    d = ast.literal_eval(text)        
    print (text)
    # check status code
    if status >=200 and status < 300:
        # extract values from message
        processingDate = d.get('processingDate')
        paymentIndicator = d.get('paymentIndicator')
        formBundleNumber = d.get('formBundleNumber')
        chargeRefNumber = d.get('chargeRefNumber')
        if not chargeRefNumber:
            chargeRefNumber = ""
    elif status >= 400 and status < 600:
        # extract errors from message
        processingDate = d.get('code')
        paymentIndicator = d.get('message')
        errors = d.get('errors')
        if errors:
            formBundleNumber = errors[0].get('code')
            chargeRefNumber = errors[0].get('message')
        else:        
            formBundleNumber = ""
            chargeRefNumber = ""
    return saveResult(filepathname, status, periodKey, processingDate, paymentIndicator, formBundleNumber, chargeRefNumber)
        
if __name__ == '__main__':
    main(sys.argv)

