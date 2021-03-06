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

logger = logging.getLogger('av_share')


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
    hostUrl = "https://www.clamav.net"
    page = br.get(hostUrl + "/reports/malware")
    page = BeautifulSoup(page.text, 'html.parser')

    form = page.find('form', action='/reports/submit')
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input')])
    form_data['sendername'] = email[:email.find("@")]
    form_data['email'] = email
    form_data['description'] = help_text
    form_data['notify'] = 'on'
    form_data['shareSample'] = 'on'

    response = br.post(hostUrl + form['action'],
                       data=form_data,
                       files={u'file': open(filename, 'rb')})
    if "Report Submitted" in response.text:
        return 0, "Success!"
    else:
        logger.warning("ClamAV error: %s - %s" % (response.status_code, response.text))
        return 1, "Something went wrong: %s" % response.status_code


def sendMicrosoft(filename, help_text, email, name):
    br = Session()
    hostUrl = "https://www.microsoft.com/en-us/security/portal/submission/submit.aspx"
    br.headers.update({'referer': hostUrl})
    page = br.get(hostUrl)

    br.get("http://c.microsoft.com/trans_pixel.aspx")  # get additional cookies

    page = BeautifulSoup(page.text, 'html.parser')
    form = page.find('form', id='Newsubmission')

    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if el.has_attr('name')])

    form_data["Name"] = email
    form_data["Product"] = "Windows Server Antimalware"
    form_data["Comments"] = help_text
    form_data["Priority"] = 2

    response = br.post(
        hostUrl, data=form_data,
        files={u'File':
               open(filename, 'rb')})

    text = response.text.encode('utf-8')

    result = text.find('window.location.href="SubmissionHistory.aspx')
    if result != -1:
        sub_url = text[result + 44:]
        sub_url = "/SubmissionHistory.aspx" + sub_url[:sub_url.find('"')]
        url = response.url[:response.url.rfind('/')] + sub_url
        return 0, "Success! Your status is <a href='%s'>here</a>" % url
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
