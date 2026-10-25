'use strict';

const bridge=window.mcAdminGate;
const restartButton=document.querySelector('#restartButton');
const restartLabel=document.querySelector('#restartLabel');
const status=document.querySelector('#gateStatus');
const error=document.querySelector('#gateError');
const actions=document.querySelector('.actions');
let pending=true,capabilityDenied=false;

function setPending(value){
  pending=value;
  restartButton.disabled=value;
  actions.setAttribute('aria-busy',String(value));
  restartLabel.textContent=value?'正在请求管理员启动…':capabilityDenied?'重新启动并核验权限':'以管理员身份重新启动';
}
function showError(message){error.textContent=message;error.hidden=false;}
function clearError(){error.textContent='';error.hidden=true;}
function restartError(code){
  if(code==='ADMIN_ELEVATION_CANCELED'||code==='ELEVATION_CANCELED')return '你已取消权限确认。软件仍保持锁定，可以重新尝试。';
  if(code==='ADMIN_CHECK_FAILED')return '无法确认管理员权限。请重试；若仍失败，请联系提供软件的人。';
  if(code==='ADMIN_CAPABILITY_DENIED')return 'Windows 未允许软件所需的管理员能力。请检查系统策略或安全软件的限制；再次提权不一定能解决。';
  return '管理员启动未完成。请重试；若仍失败，请联系提供软件的人。';
}

restartButton.addEventListener('click',async()=>{
  if(pending)return;
  setPending(true);clearError();status.textContent='请在 Windows 权限提示中选择“是”。';
  try{
    const result=await bridge.restart();
    if(result?.started===true){status.textContent='已请求管理员启动，正在等待新窗口…';return;}
    setPending(false);
    status.textContent='连接操作仍保持锁定。';
    showError(result?.canceled===true?'你已取消权限确认。软件仍保持锁定，可以重新尝试。':restartError(result?.errorCode));
  }catch{
    setPending(false);status.textContent='连接操作仍保持锁定。';showError(restartError());
  }
  restartButton.focus();
});

async function closeWindow(){
  try{await bridge.close();}catch{showError('暂时无法退出。请再次点击“退出”，或使用 Windows 任务管理器关闭 MC Proxy。');}
}
document.querySelector('#exitButton').addEventListener('click',closeWindow);
document.querySelector('#closeWindow').addEventListener('click',closeWindow);
document.querySelector('#minimizeWindow').addEventListener('click',async()=>{
  try{await bridge.minimize();}catch{showError('暂时无法最小化窗口，可以重试。');}
});

async function initialize(){
  try{
    if(!bridge||typeof bridge.info!=='function'||typeof bridge.restart!=='function')throw new Error('ADMIN_BRIDGE_UNAVAILABLE');
    const info=await bridge.info();
    if(typeof info?.productName==='string')document.querySelector('#productName').textContent=info.productName;
    if(typeof info?.version==='string')document.querySelector('#version').textContent=`v${info.version}`;
    if(info?.reason==='account-changed'){
      document.querySelector('#gateTitle').textContent='请使用原来的 Windows 账户';
      document.querySelector('#gateDescription').textContent='本次提权切换到了其他账户。为了保留原配置与授权，已停止启动。';
      restartLabel.textContent='请使用原账户重新打开';
      actions.setAttribute('aria-busy','false');
      status.textContent='请退出，然后回到原来的 Windows 账户打开 MC Proxy。';
      document.querySelector('#gateHelp').textContent='提权时请使用当前账户，不要输入其他 Windows 账户的凭据。';
      document.querySelector('#exitButton').focus();
      return;
    }
    capabilityDenied=info?.reason==='capability-denied';
    if(capabilityDenied){
      document.querySelector('#gateTitle').textContent='管理员能力验证未通过';
      document.querySelector('#gateDescription').textContent=info.adminAccess?.elevated===true&&info.adminAccess?.tokenMatched===true?'当前已具备管理员权限，但 Windows 未允许软件所需的管理员能力。连接操作保持锁定。':'Windows 未允许软件所需的管理员能力，连接操作保持锁定。';
      document.querySelector('#gateHelp').textContent='请检查系统策略或安全软件的限制，或联系提供软件的人。再次提权不一定能解决。';
      status.textContent='启动检查未通过，配置与许可保留。';
      showError(restartError('ADMIN_CAPABILITY_DENIED'));
    }else status.textContent=info?.reason==='check-failed'?'权限检查未完成，连接操作仍保持锁定。':'请以管理员身份重新启动后继续。';
    if(info?.reason==='check-failed')showError('无法确认当前管理员权限。请重新启动并确认 Windows 的权限提示。');
    setPending(false);restartButton.focus();
  }catch{
    setPending(true);restartLabel.textContent='管理员启动暂不可用';
    status.textContent='启动状态读取失败，连接操作仍保持锁定。';
    showError('请退出后重新打开 MC Proxy；若仍出现此提示，请联系提供软件的人。');
    document.querySelector('#exitButton').focus();
  }
}
initialize();
