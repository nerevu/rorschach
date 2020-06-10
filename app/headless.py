# -*- coding: utf-8 -*-
"""
    app.headless
    ~~~~~~~~~~~~

    Provides Chrome headless browser login functionality
"""
from pathlib import Path
from subprocess import call, check_output, CalledProcessError

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys


def get_def_chromedriver_path(version=None):
    executable = f"chromedriver-{version}" if version else 'chromedriver'
    command = f"which {executable}"

    try:
        _chromedriver_path = check_output(command, shell=True, encoding='utf-8')
    except CalledProcessError:
        chromedriver_path = ''
    else:
        chromedriver_path = _chromedriver_path.strip()

    return chromedriver_path


# get system specific chromedriver (currently version 78)
def get_chromedriver_path():
    operating_system = platform.system().lower()
    chromedriver_path = None

    if operating_system == 'darwin':
        operating_system = 'mac'

    unixlike = operating_system in {'mac', 'linux'}

    if unixlike:
        # TODO: make this check cross platform
        for version in CHROME_DRIVER_VERSIONS:
            _chromedriver_path = get_def_chromedriver_path(version)

            if _chromedriver_path:
                chromedriver_path = Path(_chromedriver_path)
                break

    if not chromedriver_path:
        driver_name = 'chromedriver'

        if operating_system == 'windows':
            driver_name += '.exe'

        chromedriver_path = Path.cwd() / operating_system / driver_name

    return chromedriver_path


def find_element_loop(browser, selector, count=1, max_retries=3):
    try:
        elem = browser.find_element_by_css_selector(selector)
    except NoSuchElementException as e:
        if count < max_retries:
            time.sleep(.5)
            kwargs = {"count": count + 1, "max_retries": max_retries}
            elem = find_element_loop(browser, selector, **kwargs)
        else:
            elem = None

    return elem


def headless_auth(redirect_url, prefix):
    # selectors
    if prefix == 'TIMELY':
        username_css = 'input#email'
        password_css = 'input#password'
        signin_css = '[type="submit"]'
    elif prefix == 'XERO':
        username_css = 'input[type="email"]'
        password_css = 'input[type="password"]'
        signin_css = 'button[name="button"]'

    # start a browser
    options = Options()
    options.headless = True
    chrome_path = get_chromedriver_path()

    try:
        browser = webdriver.Chrome(executable_path=chrome_path, chrome_options=options)
    except WebDriverException as e:
        if 'executable needs to be in PATH' in str(e):
            logger.error(f"chromedriver executable not found in {chrome_path}!")
        else:
            logger.error(e)
    else:
        # navigate to auth page
        browser.get(redirect_url)
        browser.implicitly_wait(3) # seconds waited for elements

        #######################################################
        # TODO: Check to see if this is required when logging
        # in without a headless browser (might remember creds).

        # add username
        username = browser.find_element_by_css_selector(username_css)
        username.clear()
        username.send_keys(app.config[f"{prefix}_USERNAME"])

        # add password
        password = browser.find_element_by_css_selector(password_css)
        password.clear()
        password.send_keys(app.config[f"{prefix}_PASSWORD"])

        # click sign in
        signIn = browser.find_element_by_css_selector(signin_css)

        # TODO: why does it stall here for timero??
        signIn.click()
        authenticated = True

        #######################################################

        if prefix == 'XERO':
            # allow access button
            access = find_element_loop(browser, 'button[value="yes"]')

            if access:
                access.click()

                # connect button
                connect = find_element_loop(browser, 'button[value="true"]')
            else:
                connect = None

            if connect:
                connect.click()
                authenticated = True
            else:
                authenticated = False

        browser.close()
        cache.set(f'{prefix}_restore_client', authenticated)
        cache.set(f'{prefix}_headless_auth_failed', not authenticated)
