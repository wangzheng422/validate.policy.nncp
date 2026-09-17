#!/usr/bin/env python3
# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Local simulated API smoke test of real federated build. Not a live Console test."""
import argparse
import json
import threading
import time
import tempfile
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from selenium import webdriver
from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait, Select

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--topology-html', type=Path, help='Optional saved Archify HTML fixture; never fetched from a cluster')
args = parser.parse_args()
TOPOLOGY_HTML = args.topology_html.read_text() if args.topology_html else '<!doctype html><html><body><h1>SIMULATED topology</h1><svg width="240" height="100"><text x="10" y="40">br-ex → ens3</text></svg></body></html>'
REQUESTS = []
OUTCOME = 'AUTO'
CONTROL_FAIL_STATUS = 0
FAIL_OVERVIEW = False
FIXTURES = {
 'overview': {'collectedAt':'SIMULATED 2026-09-16', 'enforcement':{'state':'Disabled','message':'SIMULATED: no binding'}, 'counts':{'nodes':1,'readyNodes':1,'events':1,'rules':1},'warnings':[]},
 'inventory': {'nodes':[{'name':'simulated-node','roles':['worker'],'ready':True,'protectedInterfaces':['br-ex','ens3'],'primaryPath':['br-ex','ens3'],'defaultRoutes':[{'next-hop-interface':'br-ex'}],'edges':[{'from':'br-ex','to':'ens3'}],'evidence':[{'source':'SIMULATED fixture'}],'warnings':[]}],'revision':'simulated-v1','discoveredAt':'SIMULATED','ready':True,'warnings':[]},
 'policies': {'items':[{'name':'simulated-guardrail','kind':'ValidatingAdmissionPolicy','active':False,'rules':[{'id':'protected-interface','category':'interfaces','message':'SIMULATED rule','expression':'true'}],'yaml':'# SIMULATED\nkind: ValidatingAdmissionPolicy\n'}],'candidate':{'revision':'simulated-v1','ready':True,'yaml':'# SIMULATED candidate\nkind: ConfigMap\n'},'activeRevision':'','warnings':[]},
 'events': {'items':[{'metadata':{'name':'simulated-event'},'spec':{'source':'audit-log','timestamp':'SIMULATED','username':'simulated-user','sourceIPs':['192.0.2.1'],'userAgent':'smoke-test','verb':'create','name':'simulated-nncp','action':'DENY','reason':'SIMULATED blocked protected interface','rule':'protected-interface','category':'interfaces','policy':'simulated-guardrail','binding':'simulated-binding','auditID':'SIMULATED-AUDIT','dryRun':True,'responseCode':403,'expressionIndex':0}}],'warnings':[]},
}
FIXTURES['control'] = {'state':'Disabled','bindingResourceVersion':'','candidate':{'revision':'simulated-v1','ready':True,'yaml':'# SIMULATED reviewed parameters\nkind: NetworkGuardrailParameters\n'},'approvedRevision':'','capabilities':{'canEnable':True,'canDisable':True,'canRecordEvents':True,'checks':[{'resource':'validatingadmissionpolicybindings','verb':'create','allowed':True,'reason':''}]},'warnings':[]}
FIXTURES['examples'] = {'items':[
 {'id':'protected-primary-removal','title':'SIMULATED primary removal','description':'SIMULATED unsafe proposal','yaml':'apiVersion: nmstate.io/v1\nkind: NodeNetworkConfigurationPolicy\nmetadata:\n  name: simulated-primary-removal\nspec:\n  desiredState:\n    interfaces:\n    - name: ens3\n      state: absent\n','expectedOutcome':'DENIED'},
 {'id':'dns-only','title':'SIMULATED DNS only','description':'SIMULATED safe proposal','yaml':'apiVersion: nmstate.io/v1\nkind: NodeNetworkConfigurationPolicy\nmetadata:\n  name: simulated-dns-only\nspec:\n  desiredState:\n    dns-resolver:\n      config:\n        server: [192.0.2.53]\n','expectedOutcome':'ALLOWED'}], 'warnings':[]}

HTML = '''<!doctype html><html><head><meta charset="utf-8"><title>SIMULATED plugin smoke test</title></head><body><div id="root"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script>
const getJSON = async (url,options) => {const r=await fetch(url,options);const data=await r.json();if(!r.ok){const error=new Error(data.error||'HTTP '+r.status);error.code=r.status;error.json=data;throw error;}return data;};
getJSON.post=(url,data)=>getJSON(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
window.loadPluginEntry=async (id,container)=>{await container.init({'react':{'17.0.2':{get:()=>()=>React,loaded:1}},'@openshift-console/dynamic-plugin-sdk':{'1.2.0':{get:()=>()=>({consoleFetchJSON:getJSON}),loaded:1}}}); const factory=await container.get('GuardrailPage');ReactDOM.render(React.createElement(factory().default),document.getElementById('root'));};
</script><script src="/api/plugins/network-guardrail/plugin-entry.js"></script></body></html>'''
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  REQUESTS.append(('GET',self.path))
  if self.path=='/': self.send(HTML.encode(),'text/html'); return
  if self.path in ('/react.js','/react-dom.js'):
   name=self.path[1:-3]; self.send((ROOT/f'node_modules/{name}/umd/{name}.development.js').read_bytes(),'text/javascript'); return
  if self.path.startswith('/api/plugins/network-guardrail/'):
   self.send((ROOT/'dist'/self.path.rsplit('/',1)[1]).read_bytes(),'text/javascript'); return
  if self.path.startswith('/api/proxy/plugin/network-guardrail/api/topology/'):
   node=urlsplit(self.path).path.rsplit('/',1)[-1]
   self.send(json.dumps({'node':node,'revision':'simulated-v1','renderer':'SIMULATED Archify response','warnings':[], 'html':TOPOLOGY_HTML}).encode(),'application/json'); return
  key=urlsplit(self.path).path.rsplit('/',1)[-1]
  if key=='overview' and FAIL_OVERVIEW: self.send(json.dumps({'error':'Forbidden'}).encode(),'application/json',403); return
  if key in FIXTURES: self.send(json.dumps(FIXTURES[key]).encode(),'application/json'); return
  self.send(b'not found','text/plain',404)
 def do_POST(self):
  global CONTROL_FAIL_STATUS
  body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  REQUESTS.append(('POST',self.path,body))
  if self.path.endswith('/control'):
   assert set(body)=={'mode','revision','bindingResourceVersion','confirm'} and body['confirm'] is True
   control=FIXTURES['control']
   if CONTROL_FAIL_STATUS:
    status=CONTROL_FAIL_STATUS; CONTROL_FAIL_STATUS=0
    if status==409:
     control['candidate']['revision']='simulated-v2'; control['bindingResourceVersion']='changed-elsewhere'
    self.send(json.dumps({'error':'SIMULATED control error','refreshRequired':True}).encode(),'application/json',status); return
   assert body['revision']==control['candidate']['revision'] and body['bindingResourceVersion']==control['bindingResourceVersion']
   control['state']=body['mode']; control['bindingResourceVersion']='' if body['mode']=='Disabled' else str(len(REQUESTS))
   if body['mode']!='Disabled': control['approvedRevision']=body['revision']
   FIXTURES['overview']['enforcement']={'state':body['mode'],'message':'SIMULATED '+body['mode']}
   FIXTURES['policies']['items'][0]['active']=body['mode']!='Disabled'
   self.send(json.dumps(dict(control,message='SIMULATED mode saved')).encode(),'application/json'); return
  assert self.path=='/api/proxy/plugin/network-guardrail/api/preflight' and set(body)=={'yaml'}
  outcome=OUTCOME if OUTCOME!='AUTO' else 'DENIED' if FIXTURES['control']['state']=='Deny' and 'state: absent' in body['yaml'] else 'ALLOWED'
  recorded=outcome=='DENIED' and FIXTURES['control']['capabilities']['canRecordEvents']
  event_name='simulated-preflight-'+str(len(REQUESTS)) if recorded else ''
  audit_id='SIMULATED-API-AUDIT-'+str(len(REQUESTS))
  if recorded:
   event=json.loads(json.dumps(FIXTURES['events']['items'][0])); event['metadata']['name']=event_name
   event['spec'].update(source='preflight',name='simulated-primary-removal',auditID=audit_id,reason='SIMULATED API denial',dryRun=True)
   FIXTURES['events']['items'].insert(0,event)
  result={'allowed':outcome=='ALLOWED' if outcome!='ERROR' else None,'outcome':outcome,'message':'SIMULATED '+outcome,'statusCode':201 if outcome=='ALLOWED' else 403 if outcome=='DENIED' else 422,'warnings':[],'dryRun':True,'auditID':audit_id,'eventRecorded':recorded,'eventName':event_name,'eventWarning':'SIMULATED evidence write permission denied' if outcome=='DENIED' and not recorded else ''}
  self.send(json.dumps(result).encode(),'application/json')
 def send(self,body,mime,status=200):
  self.send_response(status); self.send_header('Content-Type',mime); self.end_headers(); self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
download_dir=tempfile.TemporaryDirectory(prefix='network-guardrail-browser-')
options=webdriver.ChromeOptions()
options.add_experimental_option('prefs',{'download.default_directory':download_dir.name,'download.prompt_for_download':False})
for arg in ['--headless=new','--no-sandbox','--disable-dev-shm-usage','--window-size=1440,1100']: options.add_argument(arg)
options.set_capability('goog:loggingPrefs',{'browser':'ALL','performance':'ALL'})
driver=webdriver.Chrome(options=options)
wait=WebDriverWait(driver,15,ignored_exceptions=(StaleElementReferenceException,))
def content(text): wait.until(lambda d:text in d.find_element(By.TAG_NAME,'body').text)
def tab(text): driver.find_element(By.XPATH,f'//nav/button[normalize-space()="{text}"]').click()
def control_posts(): return [r for r in REQUESTS if r[0]=='POST' and r[1].endswith('/control')]
def set_mode(mode):
 Select(driver.find_element(By.ID,'ng-control-mode')).select_by_value(mode)
 checkbox=driver.find_element(By.CSS_SELECTOR,'.ng-confirm input')
 if not checkbox.is_selected(): checkbox.click()
 driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').click()
 content('Global mode updated')
 wait.until(lambda d:d.find_element(By.CSS_SELECTOR,'.ng-control .ng-badge').text=={'Deny':'Deny mode','Audit':'Audit mode','Disabled':'Not enforced'}[mode])
def load_example(index):
 wait.until(lambda d:len(d.find_elements(By.XPATH,'//button[text()="Load into editor"]'))==2)
 driver.find_elements(By.XPATH,'//button[text()="Load into editor"]')[index].click()
try:
 driver.get(f'http://127.0.0.1:{server.server_port}/')
 content('Not enforced'); content('Global interception control')
 assert not driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').is_enabled()
 assert not control_posts()
 print('PASS: federated plugin loads; global control needs explicit reviewed acceptance')
 for language,label,control_label in [('zh-CN','网络变更护栏','全局拦截控制'),('zh-TW','網路變更護欄','全域攔截控制'),('en','Network Guardrail','Global interception control')]:
  Select(driver.find_element(By.CSS_SELECTOR,'.ng-toolbar select')).select_by_value(language); content(label); content(control_label)
 print('PASS: Simplified Chinese, Traditional Chinese, English controls')
 FIXTURES['control']['candidate']['ready']=False
 driver.find_element(By.XPATH,'//button[text()="Refresh evidence"]').click(); content('Enabling requires complete candidate evidence')
 driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').click()
 assert not driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').is_enabled()
 assert not control_posts()
 FIXTURES['control']['candidate']['ready']=True
 driver.find_element(By.XPATH,'//button[text()="Refresh evidence"]').click()
 wait.until(lambda d:bool(d.find_elements(By.CSS_SELECTOR,'.ng-confirm input')) and not d.find_element(By.CSS_SELECTOR,'.ng-confirm input').is_selected())
 content('Global interception control')
 print('PASS: incomplete discovery cannot enable interception; readiness change requires renewed review')
 set_mode('Deny')
 assert control_posts()[-1][2]=={'mode':'Deny','revision':'simulated-v1','bindingResourceVersion':'','confirm':True}
 assert not driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').is_selected()
 driver.find_element(By.CSS_SELECTOR,'.ng-control').screenshot('/tmp/network-guardrail-control-ui.png')
 print('PASS: reviewed Deny transition sends exact optimistic-concurrency contract and refreshes state')
 wait.until(lambda d:any('/api/proxy/plugin/network-guardrail/api/topology/' in request[1] for request in REQUESTS if request[0]=='GET'))
 print('PASS: topology request is prefetched before opening Primary Network Path')
 tab('Primary Network Path'); content('simulated-node'); wait.until(lambda d:bool(d.find_elements(By.CSS_SELECTOR,'iframe[srcdoc]')))
 frame=driver.find_element(By.CSS_SELECTOR,'iframe[srcdoc]'); assert frame.get_attribute('sandbox')=='allow-scripts allow-downloads'
 assert frame.get_attribute('scrolling')=='no'
 driver.switch_to.frame(frame)
 if args.topology_html:
  wait.until(lambda d:d.execute_script('return !!window.Archify && !!Archify.view'))
  wait.until(lambda d:d.find_element(By.TAG_NAME,'html').get_attribute('data-embed')=='true')
  assert driver.execute_script('''return getComputedStyle(document.body).overflow === "hidden" &&
    document.documentElement.getAttribute("data-present") !== "true" &&
    document.scrollingElement.scrollHeight <= window.innerHeight + 8 &&
    [".toolbar", ".header", ".guided-views", ".diagram-nav"].every(function (selector) {
      var element = document.querySelector(selector);
      return !element || getComputedStyle(element).display === "none";
    });''')
  print('PASS: embedded Archify view is a clean diagram with no viewer controls')
 else:
  content('SIMULATED topology')
 driver.switch_to.default_content()
 full_link=wait.until(lambda d:d.find_element(By.CSS_SELECTOR,'[data-testid="topology-full-link"]'))
 assert full_link.get_attribute('target')=='_blank' and full_link.get_attribute('href').startswith('blob:')
 if args.topology_html:
  original_handles=set(driver.window_handles)
  full_link.click()
  wait.until(lambda d:len(d.window_handles)==len(original_handles)+1)
  full_handle=next(handle for handle in driver.window_handles if handle not in original_handles)
  driver.switch_to.window(full_handle)
  wait.until(lambda d:d.find_element(By.ID,'btn-theme'))
  initial_theme=driver.find_element(By.TAG_NAME,'html').get_attribute('data-theme')
  driver.find_element(By.ID,'btn-theme').click()
  wait.until(lambda d:d.find_element(By.TAG_NAME,'html').get_attribute('data-theme')!=initial_theme)
  driver.find_element(By.ID,'btn-present').click()
  wait.until(lambda d:d.find_element(By.TAG_NAME,'html').get_attribute('data-present')=='true')
  driver.find_element(By.TAG_NAME,'body').send_keys(Keys.ESCAPE)
  wait.until(lambda d:d.find_element(By.TAG_NAME,'html').get_attribute('data-present')!='true')
  scale=driver.execute_script('return Archify.view.state().scale')
  driver.find_element(By.TAG_NAME,'body').send_keys('+')
  wait.until(lambda d:d.execute_script('return Archify.view.state().scale')>scale)
  driver.close(); driver.switch_to.window(next(iter(original_handles)))
  print('PASS: full architecture link opens a new tab with Archify controls, presentation and zoom')
 driver.find_element(By.XPATH,'//button[text()="Present full screen"]').click(); wait.until(lambda d:d.execute_script('return !!document.fullscreenElement'))
 wait.until(lambda d:d.find_element(By.XPATH,'//button[text()="Exit full screen"]')).click()
 wait.until(lambda d:not d.execute_script('return !!document.fullscreenElement'))
 driver.find_element(By.XPATH,'//button[text()="Download interactive HTML"]').click()
 download_path=Path(download_dir.name)/'network-guardrail-simulated-node-en.html'
 wait.until(lambda d:download_path.exists())
 assert download_path.read_text()==TOPOLOGY_HTML
 print('PASS: sandboxed topology response loads, full-screen presentation and standalone HTML download work')
 tab('Policies'); content('Active binding'); driver.find_element(By.XPATH,'//summary[text()="Review YAML"]').click(); content('# SIMULATED')
 tab('History'); content('API-server audit log'); content('SIMULATED-AUDIT')
 driver.find_element(By.CSS_SELECTOR,'input[type=search]').send_keys('absent'); content('No recorded guardrail events.')
 print('PASS: policy/YAML review, audit source and actual audit ID, history filter')
 tab('Preflight'); assert not driver.find_element(By.CSS_SELECTOR,'button[type=submit]').is_enabled()
 load_example(0); assert 'name: ens3' in driver.find_element(By.TAG_NAME,'textarea').get_attribute('value')
 driver.find_element(By.CSS_SELECTOR,'button[type=submit]').click(); content('Admission rejected the request'); content('Guardrail event saved from the API-server result')
 driver.find_element(By.XPATH,'//button[text()="Open event history"]').click(); content('Preflight API result'); content('API-server audit log')
 wait.until(lambda d:bool(d.find_elements(By.CSS_SELECTOR,'tr.ng-highlight')))
 assert 'SIMULATED-API-AUDIT' in driver.find_element(By.CSS_SELECTOR,'tr.ng-highlight').text
 print('PASS: dynamic unsafe sample denied, real-result event distinguished and highlighted in refreshed history')
 tab('Preflight'); load_example(1)
 driver.find_element(By.CSS_SELECTOR,'button[type=submit]').click(); content('Dry-run accepted'); content('No Guardrail event was saved for this attempt.')
 OUTCOME='ERROR'; driver.find_element(By.CSS_SELECTOR,'button[type=submit]').click(); content('Dry-run could not be completed'); OUTCOME='AUTO'
 print('PASS: editable DNS-only sample accepted; ERROR remains distinct from admission denial')
 FIXTURES['control']['capabilities']['canRecordEvents']=False
 load_example(0); driver.find_element(By.CSS_SELECTOR,'button[type=submit]').click(); content('SIMULATED evidence write permission denied')
 content('No Guardrail event was saved for this attempt.')
 FIXTURES['control']['capabilities']['canRecordEvents']=True
 print('PASS: event recording failure is explicit and never displayed as saved')
 tab('Overview'); set_mode('Audit')
 tab('Preflight'); load_example(0); driver.find_element(By.CSS_SELECTOR,'button[type=submit]').click(); content('Dry-run accepted')
 print('PASS: Audit mode does not present unsafe sample as an enforced denial')
 tab('Overview'); CONTROL_FAIL_STATUS=409
 Select(driver.find_element(By.ID,'ng-control-mode')).select_by_value('Deny'); driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').click()
 before=len(control_posts()); driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').click(); content('The inventory or binding changed.')
 content('simulated-v2'); assert not driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').is_selected()
 time.sleep(.2); assert len(control_posts())==before+1
 print('PASS: stale409 refreshes evidence, clears review acceptance, and does not auto retry')
 CONTROL_FAIL_STATUS=403; driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').click(); driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').click(); content('Your current Console identity is not permitted')
 wait.until(lambda d:bool(d.find_elements(By.CSS_SELECTOR,'.ng-confirm input')))
 assert not driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').is_selected()
 FIXTURES['control']['capabilities']['canEnable']=False
 driver.find_element(By.XPATH,'//button[text()="Refresh evidence"]').click(); content('This identity cannot change the selected mode.')
 driver.find_element(By.CSS_SELECTOR,'.ng-confirm input').click()
 assert not driver.find_element(By.XPATH,'//button[text()="Apply selected mode"]').is_enabled()
 driver.find_element(By.XPATH,'//button[text()="Stop interception"]').click(); content('Global mode updated')
 wait.until(lambda d:d.find_element(By.CSS_SELECTOR,'.ng-control .ng-badge').text=='Not enforced')
 assert control_posts()[-1][2]['mode']=='Disabled'
 print('PASS: caller capability limits enabling; authorized stop removes interception')
 posts=[r for r in REQUESTS if r[0]=='POST']
 assert all(r[1] in ('/api/proxy/plugin/network-guardrail/api/preflight','/api/proxy/plugin/network-guardrail/api/control') for r in posts)
 assert all(set(r[2])=={'yaml'} for r in posts if r[1].endswith('/preflight'))
 print('PASS: only explicit control POST and dry-run POST; no persistent NNCP mutation endpoint')
 driver.set_window_size(600,950); tab('Primary Network Path'); content('simulated-node')
 assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
 print('PASS: narrow viewport has no page-level horizontal overflow')
 FAIL_OVERVIEW=True; tab('Overview'); driver.find_element(By.XPATH,'//button[text()="Refresh evidence"]').click(); content('Evidence could not be loaded')
 assert not driver.find_elements(By.CSS_SELECTOR,'.ng-enforcement')
 print('PASS: API read errors clear stale overview enforcement claims')
 errors=[entry for entry in driver.get_log('browser') if entry['level']=='SEVERE' and 'favicon' not in entry['message'] and not any(str(code) in entry['message'] for code in (403,409))]
 assert not errors, errors
 print('PASS: no browser JavaScript errors')
 network_messages=[json.loads(entry['message'])['message'] for entry in driver.get_log('performance')]
 requested_urls=[message['params']['request']['url'] for message in network_messages if message['method']=='Network.requestWillBeSent']
 external_urls=[url for url in requested_urls if urlsplit(url).scheme in ('http','https') and urlsplit(url).hostname not in ('127.0.0.1','localhost')]
 assert not external_urls, external_urls
 print('PASS: no external network requests from plugin or sandboxed topology')
 print('SIMULATED ONLY: no real cluster changes, authentication, live admission, or audit collection exercised.')
finally:
 driver.quit(); server.shutdown(); download_dir.cleanup()
