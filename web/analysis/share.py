# coding=utf-8
from pyminizip import compress
from requests import Session
from bs4 import BeautifulSoup
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import smtplib
import logging

logger = logging.getLogger('av_report')


def sendKaspersky(filename, help_text, email, name):
    br = Session()
    hostUrl = "https://newvirus.kaspersky.com/"
    page = br.get(hostUrl)
    page = BeautifulSoup(page.text, 'html.parser')

    form = page.find('form', id="SendForm")

    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if 'name' in el])

    form_data["cc"] = "on"
    form_data["VirLabRecordModel.Email"] = email
    form_data["VirLabRecordModel.SuspiciousFilePath"] = name
    form_data["VirLabRecordModel.CategoryValue"] = "SuspiciousFile"

    response = br.post(hostUrl + form['action'], data=form_data,
                       files={'VirLabRecordModel.SuspiciousFileContent':
                              open(filename, 'rb')})

    if "was successfully sent" in response.text:
        return 0, "Success!"
    else:
        logger.warning("Kaspersky error: %s" % response.text)
        return 1, "Something went wrong %s " % response.text


def sendDrWeb(filename, help_text, email, name):
    br = Session()
    page = br.get("https://vms.drweb.com/sendvirus/")
    page = BeautifulSoup(page.text, 'html.parser')
    form = page.find('form', id="SNForm")
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if 'name' in el])

    form_data["email"] = email
    form_data["category"] = ["2"]
    form_data["text"] = help_text
    response = br.post(form['action'], data=form_data,
                       files={'file': open(filename, 'rb')})

    if "SNForm" not in response.text:
        return 0, "Success!"
    else:
        logger.warning("Dr.WEB error: %s" % response.text)
        return 1, "%s. Something went wrong: %s" % (filename, response.text)


def sendEset(filename, help_text, email, name):
    if ".zip" not in filename:
        compress(filename, filename + ".zip", "infected", 5)
        filename += ".zip"
        name += ".zip"

    hostUrl = "https://www.esetnod32.ru/support/knowledge_base/new_virus/"
    br = Session()
    br.headers.update({'referer': hostUrl})

    page = br.get(hostUrl)
    page = BeautifulSoup(page.text, 'html.parser')

    form = page.find('form', id="new_license_activation_v")
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if el.has_attr('name')])

    form_data["email"] = email
    del form_data["suspicious_file"]
    form_data["commentary"] = help_text

    response = br.post(hostUrl, data=form_data,
                       files={u'suspicious_file': open(filename, 'rb')})

    if u"Спасибо, Ваше сообщение успешно отправлено." in response.text:
        return 0, "Success!"
    else:
        logger.warning("Eset error: %s" % response.text)
        return 1, "Something went wrong: %s" % response.text


def sendClamAV(filename, help_text, email, name):
    br = Session()
    hostUrl = "http://www.clamav.net"
    page = br.get(hostUrl + "/reports/malware")
    page = BeautifulSoup(page.text, 'html.parser')

    for _ in range(5):
        credentials = br.get(hostUrl + "/presigned")
        if credentials.status_code == 200:
            credentials = credentials.json()
            break
        import time
        time.sleep(5)
        
    submissionid = credentials["key"].split("/")[1].split("-")[0]
    form_s3 = page.find('form', id='s3Form')
    s3_url = form_s3['action']
    form_s3_data = dict([(el['name'], el.get('value', None))
                         for el in form_s3.find_all('input')])
    
    form_s3_data.update(credentials)

    s3_answer = br.post(s3_url, data=form_s3_data,
                        files={'file': open(filename, 'rb')})
    if s3_answer.status_code > 210:
        return 1, "Something wrong. s3 status = %s" % s3_answer.status_code

    form = page.find('form', id='fileData')
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input')[:-1]])
    form_data['submissionID'] = submissionid
    form_data['sendername'] = email[:email.find("@")]
    form_data['email'] = email

    response = br.post(hostUrl + form['action'], data=form_data)

    if "Report Submitted" in response.text:
        return 0, "Success!"
    else:
        logger.warning("ClamAV error: %s" % response.text)
        return 1, "Something went wrong"


def sendMicrosoft(filename, help_text, email, name):
    br = Session()
    hostUrl = "https://www.microsoft.com/security/portal/submission/submit.aspx"
    br.headers.update({'referer': hostUrl})
    page = br.get(hostUrl)

    br.get("http://c.microsoft.com/trans_pixel.aspx")  # get additional cookies

    page = BeautifulSoup(page.text, 'html.parser')
    form = page.find('form', id='aspnetForm')

    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if el.has_attr('name')])

    form_data["ctl00$ctl00$pageContent$leftside$submitterName"] = email
    form_data["ctl00$ctl00$pageContent$leftside$incorrectDetectionRb"] = "Malware"
    form_data["ctl00$ctl00$pageContent$leftside$submissionComments"] = help_text
    form_data["ctl00$ctl00$pageContent$leftside$productSelection"] = 0
    form_data["ctl00$ctl00$Header$oneMscomBlade$ctl04$Src_Source"] = 0
    form_data["ctl00$ctl00$pageContent$leftside$submitButton"] = "Submit sample"
    form_data["ctl00$ctl00$Header$oneMscomBlade$ctl04$SearchTextBox"] = ""
    form_data["__EVENTTARGET"] = ""
    form_data["__EVENTARGUMENT"] = ""

    response = br.post(
        hostUrl, data=form_data,
        files={u'ctl00$ctl00$pageContent$leftside$submissionFile':
               open(filename, 'rb')})
    response_url = response.url

    text = response.text.encode('utf-8')

    if text.find("This sample contains the following files") != -1:
        return 0, "Success! Your status is <a href='%s'>here</a>" % (response_url)
    elif text.find('<title>Submit Sample - Maximum file size exceeded</title>') != -1:
        logger.warning("Microsoft error: Maximum file size exceeded")
        return 1, "Maximum file size exceeded"
    else:
        logger.warning("Microsoft error: %s" % text)
        return 1, "Something wrong: %s" % text


def sendMcAfee(filename, help_text, email, name):
    try:
        #if ".zip" not in filename:
        compress(filename, filename + ".zip", "infected", 5)
        filename += ".zip"
        name += ".zip"
        name = name.encode("utf8")

        msg = MIMEMultipart(
            From=email,
            To="virus_research@mcafee.com",
            Subject="Potential virus",
            Date=formatdate(localtime=True)
        )
        msg.attach(MIMEText(help_text))
        with open(filename, 'rb') as archive:
            msg_attach = MIMEApplication(
                archive.read(),
                Name=name,
            )
            msg_attach.add_header('Content-Disposition', 'attachment',
                                  filename=(Header(name, 'utf-8').encode()))
            msg.attach(msg_attach)

        smtp = smtplib.SMTP("smtp")
        smtp.sendmail(email, "virus_research@mcafee.com", msg.as_string())
        smtp.close()
        return 0, "Success! %s" % name
    except Exception as e:
        logger.warning("MacAfee error: %s" % e)
        return 1, "Something went wrong: %s" % e


ANTIVIRUSES = {
    "Kaspersky": sendKaspersky,
    "DrWeb": sendDrWeb,
    "ESET-NOD32": sendEset,
    "ClamAV": sendClamAV,
    "Microsoft": sendMicrosoft,
    'McAfee': sendMcAfee,
}
