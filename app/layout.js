import './style.css';
export const metadata={title:'Race results',robots:{index:false,follow:false}};
export default function Layout({children}){return <html lang="en"><head><script dangerouslySetInnerHTML={{__html:"if(location.pathname==='/scan'){window.__slalomReceipt=location.hash.startsWith('#r=')?location.hash.slice(3):'';history.replaceState(null,'',location.pathname);}"}} /></head><body><header>RACE RESULTS</header><main>{children}</main></body></html>;}
