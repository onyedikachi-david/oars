// Native WebView regression fixture. Sample content only; this never calls the native bridge.
import {useState} from 'react';
import {createRoot} from 'react-dom/client';
import {Mosaic,MosaicWindow,type MosaicNode} from 'react-mosaic-component';
import {WorkspaceDocking,WorkspaceDragHandle} from './src/components/WorkspaceDocking';
import {WorkspaceSurfaces,WorkspacePaneSlot} from './src/components/WorkspaceSurfaces';
import {WorkspaceDockTab,WorkspaceDockTabContext} from './src/components/WorkspaceDockTab';
import {dockWorkspacePane} from './src/workspace-layout';
import 'react-mosaic-component/react-mosaic-component.css';
import './src/index.css';
const start:MosaicNode<string>={type:'split',direction:'row',children:['Alpha','Beta']};
function Check(){
 const [tree,setTree]=useState<MosaicNode<string>|null>(start);
 const [result,setResult]=useState('Ready');

 return <div style={{height:'100vh',padding:24,display:'flex',flexDirection:'column',gap:16}}>
 <h1>Native docking check · sample panes</h1>
 <button onClick={()=>{setTree(start);setResult('Ready')}}>Reset layout</button>
 <div style={{flex:1,minHeight:0}}>
 <WorkspaceSurfaces paneKeys={['Alpha','Beta']} renderPane={id=><div style={{padding:24}}>Sample pane {id}<input aria-label={'Draft '+id} defaultValue={'Local draft '+id}/></div>}>
 <WorkspaceDockTabContext.Provider value={{names:{Alpha:'Alpha',Beta:'Beta'},onSelect:()=>{}}}>
 <WorkspaceDocking enabled onStatus={setResult} onDock={(source,target,position)=>setTree(current=>dockWorkspacePane(current,source,target,position))}>
 <Mosaic className="oars-mosaic" value={tree} onChange={setTree} renderTabButton={WorkspaceDockTab} renderTabToolbarControls={()=>null}
 renderTile={(id,path)=><MosaicWindow title={id} path={path} draggable={false}
 renderToolbar={()=><div className="workspace-pane-toolbar" data-workspace-pane={id}><WorkspaceDragHandle paneKey={id} onFocusPane={()=>{}}>Drag {id}</WorkspaceDragHandle></div>}>
 <WorkspacePaneSlot paneKey={id}/>
 </MosaicWindow>}/>
 </WorkspaceDocking></WorkspaceDockTabContext.Provider></WorkspaceSurfaces>
 </div><output>{result}</output><a href="/">Open Oars workspace</a><pre>{JSON.stringify(tree)}</pre></div>
}
createRoot(document.getElementById('root')!).render(<Check/>);
