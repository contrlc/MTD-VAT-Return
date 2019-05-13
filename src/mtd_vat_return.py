'''
Created on 4 Nov 2018

@authors: Steve Webster, Barnaby Park

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
from selenium.common.exceptions import WebDriverException
from selenium.common.exceptions import ElementClickInterceptedException
from selenium.common.exceptions import ElementNotInteractableException
from selenium.common.exceptions import ElementNotSelectableException
from selenium.common.exceptions import ElementNotVisibleException
from selenium.common.exceptions import ErrorInResponseException
from selenium.common.exceptions import ImeActivationFailedException
from selenium.common.exceptions import ImeNotAvailableException
from selenium.common.exceptions import InsecureCertificateException
from selenium.common.exceptions import InvalidArgumentException
from selenium.common.exceptions import InvalidCookieDomainException
from selenium.common.exceptions import InvalidCoordinatesException
from selenium.common.exceptions import InvalidElementStateException
from selenium.common.exceptions import InvalidSelectorException
from selenium.common.exceptions import InvalidSessionIdException
from selenium.common.exceptions import InvalidSwitchToTargetException
from selenium.common.exceptions import JavascriptException
from selenium.common.exceptions import MoveTargetOutOfBoundsException
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import NoSuchAttributeException
from selenium.common.exceptions import NoSuchCookieException
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoSuchFrameException
from selenium.common.exceptions import NoSuchWindowException
from selenium.common.exceptions import RemoteDriverServerException
from selenium.common.exceptions import ScreenshotException
from selenium.common.exceptions import SessionNotCreatedException
from selenium.common.exceptions import StaleElementReferenceException
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import UnableToSetCookieException
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.common.exceptions import UnexpectedTagNameException
from selenium.common.exceptions import UnknownMethodException
import platform
import json
import urllib
import ast
import psutil
from datetime import datetime
import time
import os
import re
from http.cookiejar import EPOCH_YEAR

VERSION = '1.0'

redirect_uri = "urn:ietf:wg:oauth:2.0:oob:auto"

def get_mac_addresses(family):
    for snics in psutil.net_if_addrs().items():
        for snic in snics:
            if isinstance(snic, list):
                for snicaddr in snic:            
                    if snicaddr.family == family:
                        yield snicaddr.address

def readCredentialsData(filepathname, periodKey, filename, opt):
    # credentials text file is 3 lines long and contains the following credentials 
    if platform.system() == "Windows":            
        idx = filepathname.rfind("\\")
    else:
        idx = filepathname.rfind("/")        
    dstpathname = filepathname[:idx+1] + filename
    # open file
    try:
        f= open(dstpathname,"r")
    except IOError as e:
        if opt.DEBUG:
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
    
def fileReturn(periodKey, vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue, totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT, VATReg, access_token, api_url, opt):
    # for sandbox testing, force different period keys to allow testing of all 4 quarters
    if opt.SANDBOX:
        # convert period key
        if periodKey == "Q1":   
            period = "Q001"
        elif periodKey == "Q2":
            period = "Q002"
        elif periodKey == "Q3":
            period = "Q003"
        else:
            period = "Q004"    
    else:  
        # for production period key use MMYY format where MM is numeric value of current month, and yy is last 2 digits if current year
        month = datetime.now().strftime('%m')
        year = datetime.now().strftime('%y')
        period = month + year
    if opt.DEBUG:
        print ("period key calc'd to be: " + periodKey)
        print("VAT REG=" + VATReg)
    args = "periodKey="+period+", vatDueSales="+vatDueSales+", vatDueAcquisitions="+vatDueAcquisitions+", totalVatDue="+totalVatDue+", vatReclaimedCurrPeriod="+vatReclaimedCurrPeriod+", netVatDue="+netVatDue+", totalValueSalesExVAT="+totalValueSalesExVAT+", totalValuePurchasesExVAT="+totalValuePurchasesExVAT+", totalValueGoodsSuppliedExVAT="+totalValueGoodsSuppliedExVAT+", totalAcquisitionsExVAT="+totalAcquisitionsExVAT+", VATReg="+VATReg
    if opt.DEBUG:
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
    # public IP address of PC/laptop
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

    if opt.DEBUG:
        print ("http status = " + str(r.status_code))
    return r.status_code, r.text

def access_token_request(auth, client_id, client_secret, token_url):
    post_data = {'grant_type': 'authorization_code',
                 'code': auth,
                 'client_id' : client_id,
                 'client_secret' : client_secret,
                 'redirect_uri': redirect_uri}
    response = requests.post(token_url,
                             data=post_data)
    token_json = response.json()
    return token_json, response.status_code

def authorization_request(uri, client_id, opt):
    scope=[('write:vat'), ('read:vat')]
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(uri)
    # open web browser
    options = webdriver.ChromeOptions()
    if platform.system() == "Windows":            
        options.binary_location = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    else:
        options.binary_location = "/usr/bin/chromium-browser"
    options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(chrome_options=options)
    driver.get(authorization_url)
    # check for illegal client_id 
    if driver.title.find(""):
        if opt.DEBUG:
            print (driver.page_source)
        source = driver.page_source.split(">{")
        msg = source[1].split("}<")
        # strip out state info, not useful to user
        source = msg[0].split(",\"state")
        if opt.DEBUG:
            print (source[0])
        # close browser
        driver.quit()
        return "ERROR: " + source[0]
    try:
        element = WebDriverWait(driver, 60).until(lambda x: 'Success code=' in driver.title or 'Denied error=' in driver.title)
        if element:
            auth_code = driver.title.split("Success code=", 1).pop()
        else:
            # close browser
            driver.quit()
            return "ERROR: Failed to get Authorisation code"
    except NoAlertPresentException:
        return "ERROR: Happens when you switch to no presented alert."
    except WebDriverException:
        return "ERROR:Browser was closed"
    except ElementClickInterceptedException:
        return "ERROR: The Element Click command could not be completed because the element receiving the events is obscuring the element that was requested clicked."
    except ElementNotInteractableException:
        return "ERROR: Thrown when an element is present in the DOM but interactions with that element will hit another element do to paint order"
    except ElementNotSelectableException:
        return "ERROR: Thrown when trying to select an unselectable element."
    except ElementNotVisibleException:
        return "ERROR: Thrown when an element is present on the DOM, but it is not visible, and so is not able to be interacted with."
    except ErrorInResponseException:
        return "ERROR: Thrown when an error has occurred on the server side."
    except ImeActivationFailedException:
        return "ERROR: Thrown when activating an IME engine has failed."
    except ImeNotAvailableException:
        return "ERROR: Thrown when IME support is not available. This exception is thrown for every IME-related method call if IME support is not available on the machine."
    except InsecureCertificateException:
        return "ERROR: Navigation caused the user agent to hit a certificate warning, which is usually the result of an expired or invalid TLS certificate."
    except InvalidArgumentException:
        return "ERROR: The arguments passed to a command are either invalid or malformed."
    except InvalidCookieDomainException:
        return "ERROR: Thrown when attempting to add a cookie under a different domain than the current URL."
    except InvalidCoordinatesException:
        return "ERROR: The coordinates provided to an interactions operation are invalid."
    except InvalidElementStateException:
        return "ERROR: Thrown when a command could not be completed because the element is in an invalid state."
    except InvalidSelectorException:
        return "ERROR: Thrown when the selector which is used to find an element does not return a WebElement. Currently this only happens when the selector is an xpath expression and it is either syntactically invalid (i.e. it is not a xpath expression) or the expression does not select WebElements (e.g. “count(//input)”)."
    except InvalidSessionIdException:
        return "ERROR: Occurs if the given session id is not in the list of active sessions, meaning the session either does not exist or that it’s not active."
    except InvalidSwitchToTargetException:
        return "ERROR: Thrown when frame or window target to be switched doesn’t exist."
    except JavascriptException:
        return "ERROR: An error occurred while executing JavaScript supplied by the user."
    except MoveTargetOutOfBoundsException:
        return "ERROR: Thrown when the target provided to the ActionsChains move() method is invalid, i.e. out of document."
    except NoAlertPresentException:
        return "ERROR: Thrown when switching to no presented alert."
    except NoSuchAttributeException:
        return "ERROR: Thrown when the attribute of element could not be found."
    except NoSuchCookieException:
        return "ERROR: No cookie matching the given path name was found amongst the associated cookies of the current browsing context’s active document."
    except NoSuchElementException:
        return "ERROR: Thrown when element could not be found."
    except NoSuchFrameException:
        return "ERROR: Thrown when frame target to be switched doesn’t exist."
    except NoSuchWindowException:
        return "ERROR: Thrown when window target to be switched doesn’t exist."
    except RemoteDriverServerException:
        return "ERROR: RemoteDriverServerException"
    except ScreenshotException:
        return "ERROR: A screen capture was made impossible."
    except SessionNotCreatedException:
        return "ERROR: A new session could not be created."
    except StaleElementReferenceException:
        return "ERROR: Thrown when a reference to an element is now “stale”."
    except TimeoutException:
        return "ERROR: Autorisation request timed out"
    except UnableToSetCookieException:
        return "ERROR: Thrown when a driver fails to set a cookie."
    except UnexpectedAlertPresentException:
        return "ERROR: Thrown when an unexpected alert is appeared."
    except UnexpectedTagNameException:
        return "ERROR: Thrown when a support class did not get an expected web element."
    except UnknownMethodException:
        return "ERROR: The requested command matched a known URL but did not match an method for that URL."
    finally:
        # close browser
        driver.quit()

    if opt.DEBUG:
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
    parser.add_option('-s', '--sandbox', dest='SANDBOX', default=False, action='store_true', help='HMRC sandbox mode for testing the script [default: %default]')
    
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
    if opt.DEBUG:
        print_args = "periodKey="+periodKey+", vatDueSales="+vatDueSales+", vatDueAcquisitions="+vatDueAcquisitions+", totalVatDue="+totalVatDue+", vatReclaimedCurrPeriod="+vatReclaimedCurrPeriod+", netVatDue="+netVatDue+", totalValueSalesExVAT="+totalValueSalesExVAT+", totalValuePurchasesExVAT="+totalValuePurchasesExVAT+", totalValueGoodsSuppliedExVAT="+totalValueGoodsSuppliedExVAT+", totalAcquisitionsExVAT="+totalAcquisitionsExVAT+", VATReg="+VATReg+", filepathname=",filepathname
        print (print_args)   
    # extract filename/path
    filepathname = urllib.parse.unquote(filepathname)
    filepathname = filepathname.strip("file:")
    # check which mode script is running in
    if opt.SANDBOX:
        authorization_url = 'https://test-api.service.hmrc.gov.uk/oauth/authorize'
        token_url = 'https://test-api.service.hmrc.gov.uk/oauth/token'
        api_url = "https://test-api.service.hmrc.gov.uk/organisations/vat/"
        # get credential data
        client_id, client_secret, server_token = readCredentialsData(filepathname, periodKey, "sandbox_credentials.txt", opt)
    else:
        authorization_url = 'https://api.service.hmrc.gov.uk/oauth/authorize'
        token_url = 'https://api.service.hmrc.gov.uk/oauth/token'
        api_url = "https://api.service.hmrc.gov.uk/organisations/vat/"
        # get credential data
        client_id, client_secret, server_token = readCredentialsData(filepathname, periodKey, "prod_credentials.txt", opt)
    # check for valid client_id
    if not client_id:
        return saveResult(filepathname, 400, "invalid client_id", "", "", "", "")
    if opt.DEBUG:
        print ("client_id=" + client_id + ", client_secret=" + client_secret + ", server_token=" + server_token)
    #authorization request
    auth = authorization_request(authorization_url, client_id, opt)
    # check authorisation was successful
    if auth.find("ERROR") != -1 or auth.find("Denied error") != -1:
        # exit returning error string
        return saveResult(filepathname, 400, auth, "", "", "", "")
    #get access token
    access_token, status_code = access_token_request(auth, client_id, client_secret, token_url)
    if status_code >= 400:
        desc = access_token[u'error_description']
        err = access_token[u'error']
        return saveResult(filepathname, status_code, desc, err, "", "", "")
#    print ('access token = ' + access_token[u'access_token'])
    access_token = access_token[u'access_token']
    #send VAT return
    status, text = fileReturn(periodKey, vatDueSales, vatDueAcquisitions, totalVatDue, vatReclaimedCurrPeriod, netVatDue, totalValueSalesExVAT, totalValuePurchasesExVAT, totalValueGoodsSuppliedExVAT, totalAcquisitionsExVAT, VATReg, access_token, api_url, opt)
    # convert unicode string to dictionary
    d = ast.literal_eval(text)        
    if opt.DEBUG:
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

