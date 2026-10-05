(function(){
  "use strict";
  var ROOT=null, RO=null;
  var WINS=[
    {id:"log",   icon:"\uD83D\uDCAC", title:"History"},
    {id:"rooms", icon:"\uD83C\uDFE0", title:"Rooms"},
    {id:"users", icon:"\uD83D\uDC65", title:"Users"},
    {id:"bag",   icon:"\uD83C\uDF92", title:"Bag"}
  ];
  var state={open:{log:true,rooms:true,users:true,bag:false},
             h:{},collapsed:{},order:WINS.map(function(w){return w.id;}),
             panelCollapsed:false};

  function load(){
    try{
      var raw=localStorage.getItem("pp_viewtest");
      if(raw){var o=JSON.parse(raw);
        if(o&&typeof o==="object"){
          if(o.open)state.open=Object.assign(state.open,o.open);
          if(o.h)state.h=o.h;
          if(o.collapsed)state.collapsed=o.collapsed;
          if(Array.isArray(o.order)&&o.order.length)state.order=o.order;
          state.panelCollapsed=!!o.panelCollapsed;
        }}
    }catch(e){}
  }
  function save(){
    try{localStorage.setItem("pp_viewtest",JSON.stringify(state));}catch(e){}
  }

  function el(tag,cls,txt){
    var e=document.createElement(tag);
    if(cls)e.className=cls;
    if(txt!=null)e.textContent=txt;
    return e;
  }

  function aspectClass(w,h){
    if(!h)return "landscape";
    var r=w/h;
    if(r<0.8)return "portrait";
    if(r<=1.3)return "square";
    return "landscape";
  }

  function applyAspect(){
    if(!ROOT)return;
    var vv=window.visualViewport;
    if(vv){
      ROOT.style.height=vv.height+"px";
      ROOT.style.top=(vv.offsetTop||0)+"px";
    }else{
      ROOT.style.height="";ROOT.style.top="";
    }
    var r=ROOT.getBoundingClientRect();
    ROOT.dataset.ar=aspectClass(r.width,r.height);
    fitStageVT();
  }

  function fitStageVT(){
    var wrap=document.getElementById("vt-stagewrap");
    var cv=document.getElementById("vt-stage");
    if(!wrap||!cv)return;
    var b=wrap.getBoundingClientRect();
    var rw=parseInt(cv.dataset.rw||"900",10);
    var rh=parseInt(cv.dataset.rh||"560",10);
    var k=Math.min(b.width/rw,b.height/rh);
    if(!isFinite(k)||k<=0)k=1;
    cv.style.width=Math.max(1,Math.floor(rw*k))+"px";
    cv.style.height=Math.max(1,Math.floor(rh*k))+"px";
  }

  function winById(id){
    for(var i=0;i<WINS.length;i++)if(WINS[i].id===id)return WINS[i];
    return null;
  }

  function isPortrait(){return ROOT&&ROOT.dataset.ar==="portrait";}

  function makeWin(def){
    var w=el("div","vtwin");
    w.dataset.win=def.id;
    var head=el("div","vthead");
    head.appendChild(el("span",null,def.icon));
    head.appendChild(el("span",null,def.title));
    var car=el("span","car","\u25be");
    head.appendChild(car);
    var body=el("div","vtbody");
    body.id="vtbody-"+def.id;
    var grip=el("div","vtgrip");
    w.appendChild(head);w.appendChild(body);w.appendChild(grip);
    if(state.h[def.id])w.style.setProperty("--h",state.h[def.id]+"px");
    if(state.h[def.id+":w"])w.style.setProperty("--w",state.h[def.id+":w"]+"px");
    if(state.collapsed[def.id])w.classList.add("collapsed");
    head.addEventListener("click",function(ev){
      if(ev.target.closest("button"))return;
      if(head.dataset.moved==="1"){head.dataset.moved="0";return;}
      w.classList.toggle("collapsed");
      state.collapsed[def.id]=w.classList.contains("collapsed");
      save();
    });
    attachDrag(w,head);
    attachResize(w,grip,def.id);
    return w;
  }

  function attachResize(w,grip,id){
    var start=null;
    grip.addEventListener("pointerdown",function(e){
      var r=w.getBoundingClientRect();
      start={x:e.clientX,y:e.clientY,w:r.width,h:r.height,
             portrait:isPortrait()};
      try{grip.setPointerCapture(e.pointerId);}catch(e2){}
      e.preventDefault();e.stopPropagation();
    });
    grip.addEventListener("pointermove",function(e){
      if(!start)return;
      if(start.portrait){
        var nw=Math.max(140,start.w+(e.clientX-start.x));
        w.style.setProperty("--w",Math.round(nw)+"px");
      }else{
        var nh=Math.max(90,start.h+(e.clientY-start.y));
        w.style.setProperty("--h",Math.round(nh)+"px");
      }
    });
    function end(e){
      if(!start)return;
      var key=start.portrait?"--w":"--h";
      var cur=parseInt((w.style.getPropertyValue(key)||"0"),10);
      if(cur)state.h[id+(start.portrait?":w":"")]=cur;
      start=null;save();fitStageVT();
    }
    grip.addEventListener("pointerup",end);
    grip.addEventListener("pointercancel",end);
  }

  function attachDrag(w,head){
    var drag=null;
    head.addEventListener("pointerdown",function(e){
      if(e.target.closest("button"))return;
      var r=w.getBoundingClientRect();
      drag={x:e.clientX,y:e.clientY,moved:false,rect:r};
      head.dataset.moved="0";
      try{head.setPointerCapture(e.pointerId);}catch(e2){}
    });
    head.addEventListener("pointermove",function(e){
      if(!drag)return;
      var dx=e.clientX-drag.x, dy=e.clientY-drag.y;
      var dist=Math.abs(dx)+Math.abs(dy);
      if(!drag.moved&&dist<8)return;
      drag.moved=true;head.dataset.moved="1";
      clearMarks();
      var t=targetAt(e.clientX,e.clientY,w);
      if(t){t.node.classList.add(t.before?"drop-before":"drop-after");
            drag.target=t;}
      else drag.target=null;
    });
    function end(e){
      if(!drag)return;
      clearMarks();
      if(drag.moved&&drag.target){
        var stack=document.getElementById("vt-stack");
        var t=drag.target;
        if(t.before)stack.insertBefore(w,t.node);
        else stack.insertBefore(w,t.node.nextSibling);
        state.order=Array.prototype.map.call(
          stack.querySelectorAll(".vtwin"),function(n){return n.dataset.win;});
        save();
      }
      drag=null;
    }
    head.addEventListener("pointerup",end);
    head.addEventListener("pointercancel",end);
  }

  function clearMarks(){
    var ns=document.querySelectorAll(".vtwin");
    for(var i=0;i<ns.length;i++)
      ns[i].classList.remove("drop-before","drop-after");
  }

  function targetAt(x,y,self){
    var stack=document.getElementById("vt-stack");
    if(!stack)return null;
    var ns=stack.querySelectorAll(".vtwin");
    for(var i=0;i<ns.length;i++){
      var n=ns[i];
      if(n===self)continue;
      var r=n.getBoundingClientRect();
      if(x<r.left||x>r.right||y<r.top||y>r.bottom)continue;
      var before = isPortrait()
        ? (x < r.left + r.width/2)
        : (y < r.top + r.height/2);
      return {node:n,before:before};
    }
    return null;
  }

  function renderStack(){
    var stack=document.getElementById("vt-stack");
    if(!stack)return;
    stack.innerHTML="";
    for(var i=0;i<state.order.length;i++){
      var def=winById(state.order[i]);
      if(!def)continue;
      if(!state.open[def.id])continue;
      stack.appendChild(makeWin(def));
    }
    syncRail();
    fitStageVT();
  }

  function syncRail(){
    var rail=document.getElementById("vt-rail");
    if(!rail)return;
    var bs=rail.querySelectorAll("button[data-win]");
    for(var i=0;i<bs.length;i++){
      var id=bs[i].dataset.win;
      bs[i].classList.toggle("on",!!state.open[id]);
      bs[i].classList.toggle("has-badge",
        !!state.open[id]&&!!state.panelCollapsed);
    }
  }

  function toggleWinVT(id){
    state.open[id]=!state.open[id];
    if(state.open[id]&&state.panelCollapsed){
      state.panelCollapsed=false;
      ROOT.classList.remove("p-collapsed");
    }
    save();renderStack();
  }

  function togglePanel(){
    state.panelCollapsed=!state.panelCollapsed;
    ROOT.classList.toggle("p-collapsed",state.panelCollapsed);
    save();syncRail();
    requestAnimationFrame(fitStageVT);
  }

  function build(){
    var root=el("div");root.id="vt";
    var rail=el("div");rail.id="vt-rail";
    for(var i=0;i<WINS.length;i++){
      (function(def){
        var b=el("button",null,null);
        b.dataset.win=def.id;
        b.title=def.title;
        b.appendChild(el("span",null,def.icon));
        b.appendChild(el("span","bdg"));
        b.addEventListener("click",function(){toggleWinVT(def.id);});
        rail.appendChild(b);
      })(WINS[i]);
    }
    var sep=el("div");sep.style.cssText="height:8px;flex:0 0 auto";
    rail.appendChild(sep);
    var tp=el("button",null,null);
    tp.id="vt-togglepanel";tp.title="Panelspalte";
    tp.appendChild(el("span",null,"\u25A4"));
    tp.appendChild(el("span","bdg"));
    tp.addEventListener("click",togglePanel);
    rail.appendChild(tp);

    var panel=el("div");panel.id="vt-panel";
    var ph=el("div","vt-head");
    ph.appendChild(el("span",null,"Windows"));
    var pb=el("button",null,"\u2194");
    pb.addEventListener("click",togglePanel);
    ph.appendChild(pb);
    var stack=el("div");stack.id="vt-stack";
    panel.appendChild(ph);panel.appendChild(stack);

    var sw=el("div");sw.id="vt-stagewrap";
    var cv=document.createElement("canvas");
    cv.id="vt-stage";cv.width=900;cv.height=560;
    cv.dataset.rw="900";cv.dataset.rh="560";
    sw.appendChild(cv);

    var aux=el("div");aux.id="vt-aux";

    var bar=el("div");bar.id="vt-bar";
    var st=el("div");st.id="vt-status";
    st.appendChild(el("span",null,"\u2014"));
    var inp=el("div");inp.id="vt-input";
    var field=document.createElement("input");
    field.type="text";field.id="vt-field";
    field.placeholder="Type here and press Enter \u2026";
    var send=el("button",null,"Say");
    inp.appendChild(field);inp.appendChild(send);
    bar.appendChild(st);bar.appendChild(inp);

    root.appendChild(rail);root.appendChild(panel);
    root.appendChild(sw);root.appendChild(aux);root.appendChild(bar);
    return root;
  }

  function mount(){
    if(ROOT)return ROOT;
    load();
    ROOT=build();
    document.body.appendChild(ROOT);
    if(state.panelCollapsed)ROOT.classList.add("p-collapsed");
    renderStack();
    applyAspect();
    if(window.ResizeObserver){
      RO=new ResizeObserver(applyAspect);
      RO.observe(ROOT);
    }
    window.addEventListener("resize",applyAspect);
    if(window.visualViewport){
      window.visualViewport.addEventListener("resize",applyAspect);
      window.visualViewport.addEventListener("scroll",applyAspect);
    }
    return ROOT;
  }

  function unmount(){
    if(!ROOT)return;
    if(RO){try{RO.disconnect();}catch(e){}RO=null;}
    window.removeEventListener("resize",applyAspect);
    if(window.visualViewport)
      window.visualViewport.removeEventListener("resize",applyAspect);
    ROOT.remove();ROOT=null;
  }

  window.ViewTest={
    mount:mount,
    unmount:unmount,
    refit:fitStageVT,
    body:function(id){return document.getElementById("vtbody-"+id);},
    setRoomSize:function(w,h){
      var cv=document.getElementById("vt-stage");
      if(!cv)return;
      cv.dataset.rw=String(w||900);cv.dataset.rh=String(h||560);
      cv.width=w||900;cv.height=h||560;
      fitStageVT();
    },
    isMounted:function(){return !!ROOT;}
  };
})();
