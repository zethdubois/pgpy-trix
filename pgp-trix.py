# pgp-trix.py

#--about-------------------------------------------
#
#   an in-App secure(?) PGP message system
#   see conrad's svelte JS example:
#   https://browser.conrads.website/board8/
#
#--about pgp----------------
#
#   https://pgpy.readthedocs.io/en/latest/api.html
#
#   >> uid = pgpy.PGPUID.new('Nikola Tesla') << comment is option, either email or name must be provided

import PySimpleGUI as sg
import inspect
from sys import platform
import os
from datetime import datetime

# -- pip installable
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import hexdump

#--SYSTEM VARS--------------
SSH_PATH = ''
OS_VAR = ''

#--STATE VARS----------------
key_loaded = False
key_hidden = "concealed"
enab_sign = enab_gen = name = msg = email = 0
key = ''
fingerprint = ''
window = ''

#--MESSAGES--------------------------------
keygen_msg = "Key securely generated in-App"
app_key_msg = "App Key @"
app_intro = "PGP Python initialized. \n** NAME or EMAIL minimum requirement for generating PGP RSA 4096"

#--COUNTERS---
tcnt = 1

#--UI--------------------------------
#--styles-----
#-color
sg.theme('DarkGrey1')
bc1 = ("black","powder blue")
bc2 = ("black","spring green")
bc2d = ("black","DarkSeaGreen4")
c1 = "sky blue"
con_tc = 'white'
con_bc = 'midnight blue'
# f1 = ("Cascadia Mono SemiBold",9)
f1 = "" #("System", 9)
f3 = ("System", 9, "bold")
tf1 = ("Helvetica", 10)
tf1i = ("Helvetica", 10, "italic")
f2 = ("Consolas", 9, "italic")
con_f = ("Consolas", 8)
subdued = "grey50"
ic1 = 'light goldenrod yellow'
ts1 = 10
is1 = 45

#-format
no_size = (None,None)
no = None

#--DEBUG--------------------------------
verbose = False
debug = 0   # 1 = all print trace statements, 
            # 2 = includes event tracing
            # 3 = includes function tracing

#==FUNCTIONS==================================

def vprint(feed, namespace=None): #: vprint is for deep debugging 
# feed is a literal object or could be a string/int value
# NAMESPACE (opt), disinclude for general printout trace
    if debug == 0:  #: skip funct with no dubug
        return

    global tcnt
    msg = ''

    if namespace:   # this is a variable report
        for v in feed:
            if v:
                buff = v
                v = [name for name in namespace if namespace[name] is v]
                msg += str(v) + " = " + str(buff) + ", "
        msg = msg[:-2]
        print((str(tcnt)+"-->"),msg)
        tcnt += 1
    else:
        for m in feed:
            if m:
                msg += m + ", "
        msg=msg[:-2]
        print((str(tcnt)+":"), msg)
        tcnt += 1

def trace_out(trace, parms):
    global tcnt
    if debug > 2:
        print("\n"+(str(tcnt)+"***"), trace, "(", parms, ")")
        tcnt += 1

def welcome():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")    
    status_msg([OS_VAR,SSH_PATH])
    status_msg([app_intro])

def define_lo():

    fields_lo = [
      [sg.Text('Name', key='-name-', size=(ts1,1), justification='r', font=tf1), 
      sg.Input(key='-NAME-', s=(is1,1), enable_events=True, background_color=ic1, use_readonly_for_disable=False)],
      [sg.Text('Email', key='-email-', size=(ts1,1), justification='r', font=tf1), 
      sg.Input(key='-EMAIL-', s=(is1,1), enable_events=True, background_color=ic1, use_readonly_for_disable=False)],
      [sg.Text('Comment', key='-comment-', size=(ts1,1), justification='r', font=tf1), 
      sg.Input(key='-COMMENT-', s=(is1,1), enable_events=True, background_color=ic1, use_readonly_for_disable=False)],  
      [sg.Text('Message', size=(ts1,1), justification='r', font=tf1), 
      sg.Multiline(key='-MSG-', s=(is1,6), no_scrollbar=True, enable_events=True, background_color=ic1)]  ]

    #! see this ridiculous solution for FileBrowse button class having zero event handler:
    #- https://github.com/PySimpleGUI/PySimpleGUI/issues/850
    switches_lo = [
      [sg.Button('Generate Key', button_color=bc1, font=f1, key='-GEN-', tooltip="Name or Email needed"), 
      sg.Text('Generate an App key or...', s=(35,1), auto_size_text=True, key='-APPKEY-', font=f2, text_color="grey50")],
      [sg.Input(key='-LOAD-', enable_events=True, visible=False),
      sg.FileBrowse('Load Key File', target='-LOAD-', button_color=bc2, font=f1, key='-BROWSE-', 
        file_types = (('Armored ASCII', '*.asc'),), initial_folder=SSH_PATH, tooltip=SSH_PATH), 
      sg.Text('select an armored ascii filekey', key='-FILEKEY-', font=f2, text_color="grey50")]  ]

    submit_lo = [
      [sg.Button('sign / encrypt', key="-SIGN-"), 
      sg.Button('verify / decrypt', key="-VERIFY-")]]

    pub_lo = [
      [sg.Multiline(s=(45,4), key='-PUB-', enable_events=True, background_color='grey')] ]

    priv_lo = [
      [sg.Multiline(s=(45,4), key='-PRIV-', enable_events=True, background_color='grey')] ]

    keys_lo = [
      [sg.Text('no key loaded', key='-FINGERPRINT-', s=(is1,1), font=f2, auto_size_text=True, text_color=subdued)],
      [sg.Frame(title='Public Key', layout=pub_lo, relief="flat")],
      [sg.Checkbox('reveal', key='-REVEAL-', enable_events=True)],
      [sg.Frame(title='Private Key', layout=priv_lo, relief="flat")]  ]

    pane1_lo = [
      [sg.Text("Python PGP")], 
      [sg.Column(layout=switches_lo)], #, background_color="pink")], # BG 4 troubleshoot
      [sg.Column(layout=fields_lo)]  ] # end pane1

    pane2_lo = [
      [sg.Column(layout=submit_lo)],
      [sg.Column(layout=keys_lo)]  ]

    col_lo = [
      [sg.Column(layout=pane1_lo, background_color=""), 
      sg.Column(layout=pane2_lo, background_color="")],
      [sg.Multiline('', s=(45,5), autoscroll=True, key='-CONSOLE-', enable_events=True, font=con_f, background_color=con_bc, text_color=con_tc, no_scrollbar=True)]    ] 

    window = sg.Window('Window Title', layout=col_lo, default_element_size=(12,1), finalize=True)
    window['-CONSOLE-'].expand(True, True)
    return window

#--STARTUP---------------find ssh directory and OS
def startup():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")  

    if platform == "linux" or platform == "linux2":
        ver = "Linux"
    elif platform == "darwin":
        ver = "OS X"
    elif platform == "win32":
        ver = "Windoze"
        path = os.path.join(os.environ['USERPROFILE'], ".ssh")
    if os.path.exists(path):
        vprint(["local ssh directory discovered",path])
    else:
        path = ''   # os.environ['USERPROFILE'] #<--other OS syntax not yet known
        ver = "operating system unknown"
    return path, ver

def lock_key():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")

    window['-BROWSE-'].update(disabled=True) 
    window['-BROWSE-'].update(button_color=bc2d)
    window['-GEN-'].update(disabled=False)
    window['-GEN-'].update(button_color="pink")  
    window['-GEN-'].update('CLEAR KEY')

    window['-FILEKEY-'].update('')

    window['-NAME-'].update(disabled=True)
    window['-NAME-'].Widget.config(disabledbackground='pink')        
    window['-name-'].update(font=tf1i)
 
    window['-EMAIL-'].update(disabled=True)
    window['-EMAIL-'].Widget.config(disabledbackground='pink')
    window['-email-'].update(font=tf1i)

    window['-COMMENT-'].update(disabled=True)
    window['-COMMENT-'].Widget.config(disabledbackground='pink')
    window['-comment-'].update(font=tf1i)       

#--UPDATE_UI---------------------RUN FROM EVENT WHILE LOOP
def update_UI():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")

    if enab_sign > 1:
        window['-SIGN-'].update(disabled=False)
    else:
        window['-SIGN-'].update(disabled=True)


    if enab_gen > 0:
        window['-GEN-'].update(disabled=False)
    else:
      window['-GEN-'].update(disabled=True)        

    if key_loaded:
        lock_key() 

    if window['-REVEAL-'].get():
        window['-PRIV-'].update(value=key) 
    else:
        if key_loaded:
            # key_hidden = "concealed"
            window['-PRIV-'].update(value=key_hidden)
    window['-FINGERPRINT-'].update(value=fingerprint)


#--STATUS_MSG()------------send messages to the status field
def status_msg(feed, lead=None, error=None):  
# FEED is a list 
# LEAD [opt] = True if first msg in a series
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,[feed, lead, error])  

    prior = window['-CONSOLE-'].get()
    if lead:
      prior += "\n> "
    msg = prior
    for m in feed:
        if m:
          msg += m + ", "
    msg = msg[:-2]      

    if error:
        window['-CONSOLE-'].update(background_color='IndianRed4')
    else:
        window['-CONSOLE-'].update(background_color=con_bc)
    window['-CONSOLE-'].update(value=msg) 

#--CLEAR_KEY()------------clear App key, reset switches
def clear_key():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")    

    key = "" 
    feedback = status_msg(["App key cleared"], True)
    window['-BROWSE-'].update(button_color=bc2)
    window['-BROWSE-'].update(disabled=False)
    window['-FILEKEY-'].update(visible=True)   
    window['-GEN-'].update('Generate Key')
    window['-GEN-'].update(button_color=bc1)

    window['-NAME-'].update(disabled=False)        
    window['-name-'].update(font=tf1)
    window['-EMAIL-'].update(disabled=False)
    window['-email-'].update(font=tf1)
    window['-COMMENT-'].update(disabled=False)
    window['-comment-'].update(font=tf1)

    window['-FINGERPRINT-'].update(value='no key loaded')
    window['-APPKEY-'].update(value='Generate an App key or...')
    window['-FILEKEY-'].update(value='select an armored ascii filekey')
    window['-CONSOLE-'].update(value=feedback)    
    window['-PUB-'].update(value="")
    window['-PRIV-'].update(value="")

#--GET_TIME()-------------timestamp for H M S
def get_time():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")   

    now = datetime.now()
    xtime = now.strftime("%H:%M:%S")
    return xtime

#--FILE_KEY()---------------find .asc file, set path
def file_key():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")

    path = window['-LOAD-'].get()

    vprint([path],locals())

    return path        

#--GEN_ENCRYPT()---------------button function, two modes
def gen_encrypt():
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,"")

    clear_txt = window['-MSG-'].get()

    msg = pgpy.PGPMessage.new(clear_txt)
    msg.message == clear_txt

    # binary message format
    hexdump.hexdump(bytes(msg))

    # roundtrip binary encode/decode works
    bytes(msg) == bytes(pgpy.PGPMessage.from_blob(bytes(msg)))

    # ascii message format
    print(str(msg))

    # roundtrip ASCII encode/decode works
    str(msg) == str(pgpy.PGPMessage.from_blob(str(msg)))

    # msg |= key.sign(msg)

    # sg.popup_ok_cancel('popup')
    sg.popup_scrolled(msg, title='Message Cypher', size=(40,20))

    # you must use the | operator to attach the signature.
    # the following does NOT work:
    #
    #    signed_msg = priv_key.sign(msg)

    print(str(msg))

#--GEN_KEY()---------------button function, two modes
def gen_key(gen):
    trace=(inspect.currentframe().f_code.co_name)
    trace_out(trace,[gen])    

    vprint([key_loaded], globals())

    if key_loaded:  # this pass is a clear key command, not a gen key command
        clear_key()
        loaded = False
        k = ''
        fp = ''
        return loaded,k,fp
    # ----------  
    else:
        xtime = get_time()
        appkey_status = app_key_msg + xtime

        name = values['-NAME-']
        comment = values['-COMMENT-']
        email = values['-EMAIL-']

        if gen: #<- for generating keys, not loading
            #. generating a primary key. could be DSA or ECDSA as well
            k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
            #. key doesn't have a user ID yet, and therefore is not yet usable!
            uid = pgpy.PGPUID.new(name, comment=comment, email=email)

            #. add the new user id to the key. specify all preferences at this point
            #- because PGPy doesn't have any built-in key preference defaults at this time
            #- this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
            k.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
              hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
              ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
              compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
        else:   #<- for loading keys, not generating
            try:
                #.D: read doc > https://pgpy.readthedocs.io/en/latest/api.html
                k, others = pgpy.PGPKey.from_file(KEY_PATH)
                # f = open(KEY_PATH, 'r')
                # buff=(f.read()).strip()
                # key = pgpy.PGPKey()
                # key.parse(buff)
            except OSError as err:
                print("OS error: {0}".format(err))
            except ValueError:
                status_msg(["File does not contain a valid RSA encryption key."], True, True)
                return False, '', ''
            except:
                print("Unexpected error:", sys.exc_info()[0])
                raise

        #i! https://pysimplegui.readthedocs.io/en/latest/call%20reference/#window
        # try using window.fill to fill in input fields with the loaded key data ()
# MESS------------------        
        # print(others)
        # print(key.get_uid)
        # print(type(key.get_uid))
        # print(key.get_uid(name)) # does nothing
        # print(key.get_uid(email))
        # # print(pgpy.get_uid(key)) #crash
        # print(key.get_uid('no friction'))

        # print(key.get_uid('nofriction@pm.me')) # returns a yes
        # # boo = pgpy.PGPUID.get_uid(key)# crash 
        # # boo = pgpy.get_uid(key) # crash
        # name = pgpy.PGPKey.from_file(KEY_PATH)
        # print(name)
# END MESS------------------
        # pgpy.PGPKey.pub.verify("hi")
        uid = k.get_uid
        # key.pubkey.verify(uid)

        # ASCII armored public key
#---<no crash        
        # pub = key.pubkey
        # print(pub)
        # print(pub.get_uid)
        # print(str(pub.get_uid(name)))
        # print(str(pub.get_uid(email)))
        # print(key.fingerprint)
        # print(key.get_uid(name))
        # print(key.get_uid('name'))
        # print(key.get_uid(email))
        # keyring = PGPKeyring(KEY_PATH)
#  no crash />         

# with keyring.key(GNUPG_IDENTITY) as key:
#     for userid in key.userids:
#         print(userid.name)

        loaded = True
        # fingerprint = key.fingerprint[0:24]+"..."
        fp = k.fingerprint        
        if gen:
            status_msg([keygen_msg], True)
            window['-APPKEY-'].update(value=appkey_status)
        else:
            key_file = KEY_PATH.split('/')[-1]  #: get last element in split list
            window['-APPKEY-'].update(value=key_file)
            status_msg(["Armored ASCII key file loaded", KEY_PATH], True)
        status_msg([name,email,comment])
        status_msg([k.fingerprint])
        window['-PUB-'].update(value=k.pubkey)  
        return loaded, k, fp

#==MAIN============================================
# **** RUN STARTUP TO ESTABLISH REQUISITE VARIABLES
SSH_PATH, OS_VAR = startup()
window = define_lo()
welcome()

#--EVENT HANDLER-------------
while True:             # Event Loop
    update_UI()

    d = ''
    event, values = window.read()

    if event in (None, 'exit'):
        break

    if debug > 1:
        try:
            d = window[event].get()
        except Exception:
            vprint(["window event element did not have a value"])
            pass
        vprint(["{EVENT}",event,d])
        if verbose: 
            print(values)


    #--Switch Events
    if event == '-GEN-':
        vprint(["Generate Key"])
        key_loaded, key, fingerprint = gen_key(True)

    elif event == '-LOAD-':
        vprint(["Load File Key"])
        KEY_PATH = file_key() 
        key_loaded, key, fingerprint = gen_key(False)

    elif event == '-SIGN-':
        vprint(["Sign/Encrypt"])
        gen_encrypt() 


    #--Field Events
    elif event == '-NAME-':
        name = values['-NAME-']
        if name == '':
            name = 0
            window['-NAME-'].update(background_color='grey')
        else: 
            name = 1
            window['-NAME-'].update(background_color=c1)
    elif event == '-EMAIL-':
        email = values['-EMAIL-']
        if email == '':
            email = 0
            window['-EMAIL-'].update(background_color='grey')
        else: 
            email = 1
            window['-EMAIL-'].update(background_color=c1)  
    elif event == '-COMMENT-':
        comment = values['-COMMENT-']
        if comment == '':
            window['-COMMENT-'].update(background_color='grey')
        else: 
            window['-COMMENT-'].update(background_color=c1)            
    elif event == '-MSG-':
        msg = values['-MSG-']      
        if msg == '\n':
            msg = 0
            window['-MSG-'].update(background_color='grey')
        else: 
            msg = 1
            window['-MSG-'].update(background_color=c1)
    enab_gen = email + name
    enab_sign = msg + key_loaded

window.close()


#-  improve -
#   it seems like the event handler, and the format langugage for manipulting the appearance
#   of the gui elements could use a class object handler
