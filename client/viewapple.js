(function(){
  "use strict";
  var ROOT=null,RO=null;
  var CARDS=[
    {id:"log",  icon:"\uD83D\uDCAC",title:"History"},
    {id:"rooms",icon:"\uD83C\uDFE0",title:"Rooms"},
    {id:"users",icon:"\uD83D\uDC65",title:"Users"},
    {id:"bag",  icon:"\uD83C\uDF92",title:"Bag"}
  ];
  var S={open:{log:true,rooms:true,users:true,bag:false},
         size:{},collapsed:{},order:CARDS.map(function(c){return c.id;}),
         sideCollapsed:false};

  function load(){
    try{var r=localStorage.getItem("pp_viewapple");
      if(!r)return;
      var o=JSON.parse(r);
      if(!o||typeof o!=="object")return;
      if(o.open)S.open=Object.assign(S.open,o.open);
      if(o.size)S.size=o.size;
      if(o.collapsed)S.collapsed=o.collapsed;
      if(Array.isArray(o.order)&&o.order.length)S.order=o.order;
      S.sideCollapsed=!!o.sideCollapsed;
    }catch(e){}
  }
  function save(){
    try{localStorage.setItem("pp_viewapple",JSON.stringify(S));}catch(e){}
  }
  function el(t,c,x){var e=document.createElement(t);
    if(c)e.className=c; if(x!=null)e.textContent=x; return e;}
  function byId(id){for(var i=0;i<CARDS.length;i++)
    if(CARDS[i].id===id)return CARDS[i];return null;}
  function portrait(){return ROOT&&ROOT.dataset.ar==="portrait";}

  function classify(w,h){
    if(!h)return "landscape";
    var r=w/h;
    if(r<0.8)return "portrait";
    if(r<=1.3)return "square";
    return "landscape";
  }

  function layout(){
    if(!ROOT)return;
    var vv=window.visualViewport;
    if(vv){ROOT.style.height=vv.height+"px";
           ROOT.style.top=(vv.offsetTop||0)+"px";}
    else {ROOT.style.height="";ROOT.style.top="";}
    var r=ROOT.getBoundingClientRect();
    ROOT.dataset.ar=classify(r.width,r.height);
    fit();
  }

  function fit(){
    var wrap=document.getElementById("va-stagewrap");
    var cv=document.getElementById("va-stage");
    if(!wrap||!cv)return;
    var b=wrap.getBoundingClientRect();
    var rw=parseInt(cv.dataset.rw||"900",10);
    var rh=parseInt(cv.dataset.rh||"560",10);
    var k=Math.min(b.width/rw,b.height/rh);
    if(!isFinite(k)||k<=0)k=1;
    cv.style.width=Math.max(1,Math.floor(rw*k))+"px";
    cv.style.height=Math.max(1,Math.floor(rh*k))+"px";
  }

  function makeCard(def){
    var c=el("div","vacard va-mat");
    c.dataset.card=def.id;
    var h=el("div","vahead");
    h.appendChild(el("span",null,def.icon));
    h.appendChild(el("span",null,def.title));
    h.appendChild(el("span","car","\u203A"));
    var body=el("div","vabody");body.id="vabody-"+def.id;
    var grip=el("div","vagrip");
    c.appendChild(h);c.appendChild(body);c.appendChild(grip);
    if(S.size[def.id])c.style.setProperty("--h",S.size[def.id]+"px");
    if(S.size[def.id+":w"])c.style.width=S.size[def.id+":w"]+"px";
    if(S.collapsed[def.id])c.classList.add("collapsed");
    h.addEventListener("click",function(ev){
      if(ev.target.closest("button"))return;
      if(h.dataset.moved==="1"){h.dataset.moved="0";return;}
      c.classList.toggle("collapsed");
      S.collapsed[def.id]=c.classList.contains("collapsed");save();
    });
    resizer(c,grip,def.id);
    mover(c,h);
    return c;
  }

  function resizer(card,grip,id){
    var st=null;
    grip.addEventListener("pointerdown",function(e){
      var r=card.getBoundingClientRect();
      st={x:e.clientX,y:e.clientY,w:r.width,h:r.height,p:portrait()};
      try{grip.setPointerCapture(e.pointerId);}catch(x){}
      e.preventDefault();e.stopPropagation();
    });
    grip.addEventListener("pointermove",function(e){
      if(!st)return;
      if(st.p){
        var w=Math.max(180,Math.min(900,st.w+(e.clientX-st.x)));
        card.style.width=Math.round(w)+"px";
        card.style.flexBasis=Math.round(w)+"px";
      }else{
        var h=Math.max(96,Math.min(1400,st.h+(e.clientY-st.y)));
        card.style.setProperty("--h",Math.round(h)+"px");
      }
    });
    function done(){
      if(!st)return;
      if(st.p)S.size[id+":w"]=Math.round(card.getBoundingClientRect().width);
      else S.size[id]=parseInt(card.style.getPropertyValue("--h"),10)||0;
      st=null;save();fit();
    }
    grip.addEventListener("pointerup",done);
    grip.addEventListener("pointercancel",done);
  }

  function marksOff(){
    var n=document.querySelectorAll(".vacard");
    for(var i=0;i<n.length;i++)n[i].classList.remove("dz-a","dz-b");
  }

  function dropTarget(x,y,self){
    var stack=document.getElementById("va-stack");
    if(!stack)return null;
    var n=stack.querySelectorAll(".vacard");
    for(var i=0;i<n.length;i++){
      var c=n[i];
      if(c===self)continue;
      var r=c.getBoundingClientRect();
      if(x<r.left||x>r.right||y<r.top||y>r.bottom)continue;
      var before=portrait()?(x<r.left+r.width/2):(y<r.top+r.height/2);
      return {node:c,before:before};
    }
    return null;
  }

  function mover(card,head){
    var d=null;
    head.addEventListener("pointerdown",function(e){
      if(e.target.closest("button"))return;
      d={x:e.clientX,y:e.clientY,moved:false,t:null};
      head.dataset.moved="0";
      try{head.setPointerCapture(e.pointerId);}catch(x){}
    });
    head.addEventListener("pointermove",function(e){
      if(!d)return;
      if(!d.moved&&Math.abs(e.clientX-d.x)+Math.abs(e.clientY-d.y)<10)return;
      d.moved=true;head.dataset.moved="1";
      marksOff();
      d.t=dropTarget(e.clientX,e.clientY,card);
      if(d.t)d.t.node.classList.add(d.t.before?"dz-a":"dz-b");
    });
    function done(){
      if(!d)return;
      marksOff();
      if(d.moved&&d.t){
        var stack=document.getElementById("va-stack");
        if(d.t.before)stack.insertBefore(card,d.t.node);
        else stack.insertBefore(card,d.t.node.nextSibling);
        S.order=Array.prototype.map.call(stack.querySelectorAll(".vacard"),
          function(n){return n.dataset.card;});
        save();
      }
      d=null;
    }
    head.addEventListener("pointerup",done);
    head.addEventListener("pointercancel",done);
  }

  function renderStack(){
    var stack=document.getElementById("va-stack");
    if(!stack)return;
    stack.innerHTML="";
    for(var i=0;i<S.order.length;i++){
      var def=byId(S.order[i]);
      if(!def||!S.open[def.id])continue;
      stack.appendChild(makeCard(def));
    }
    railSync();fit();
  }

  function railSync(){
    var rail=document.getElementById("va-rail");
    if(!rail)return;
    var bs=rail.querySelectorAll("button[data-card]");
    for(var i=0;i<bs.length;i++){
      var id=bs[i].dataset.card;
      bs[i].classList.toggle("on",!!S.open[id]);
      bs[i].classList.toggle("badge",!!S.open[id]&&!!S.sideCollapsed);
      bs[i].setAttribute("aria-pressed",S.open[id]?"true":"false");
    }
    var tg=document.getElementById("va-toggleside");
    if(tg)tg.classList.toggle("on",!S.sideCollapsed);
  }

  function toggleCard(id){
    S.open[id]=!S.open[id];
    if(S.open[id]&&S.sideCollapsed)setSide(false);
    save();renderStack();
  }
  function setSide(on){
    S.sideCollapsed=!on;
    ROOT.classList.toggle("side-collapsed",S.sideCollapsed);
    save();railSync();requestAnimationFrame(fit);
  }

  function build(){
    var root=el("div");root.id="va";
    try{if(localStorage.pp_theme_auto==="1")root.classList.add("auto");}catch(e){}

    var rail=el("div","va-mat");rail.id="va-rail";
    rail.setAttribute("role","tablist");
    for(var i=0;i<CARDS.length;i++){
      (function(def){
        var b=el("button");
        b.dataset.card=def.id;b.type="button";
        b.setAttribute("role","tab");b.title=def.title;
        b.appendChild(el("span","ic",def.icon));
        b.appendChild(el("span","lb",def.title));
        b.appendChild(el("span","dot"));
        b.addEventListener("click",function(){toggleCard(def.id);});
        rail.appendChild(b);
      })(CARDS[i]);
    }
    var tg=el("button");tg.id="va-toggleside";tg.type="button";
    tg.title="Seitenspalte";
    tg.appendChild(el("span","ic","\u25A4"));
    tg.appendChild(el("span","lb","Spalte"));
    tg.appendChild(el("span","dot"));
    tg.addEventListener("click",function(){setSide(S.sideCollapsed);});
    rail.appendChild(tg);

    var side=el("div");side.id="va-side";
    var sh=el("div");sh.id="va-sidehead";
    sh.appendChild(el("span",null,"Windows"));
    var sb=el("button",null,"Ausblenden");sb.type="button";
    sb.addEventListener("click",function(){setSide(S.sideCollapsed);});
    sh.appendChild(sb);
    var stack=el("div");stack.id="va-stack";
    side.appendChild(sh);side.appendChild(stack);

    var sw=el("div");sw.id="va-stagewrap";
    var cv=document.createElement("canvas");
    cv.id="va-stage";cv.width=900;cv.height=560;
    cv.dataset.rw="900";cv.dataset.rh="560";
    var sbar=el("div");sbar.id="va-stagebar";
    var ttl=el("span","title","Lobby");ttl.id="va-roomtitle";
    sbar.appendChild(ttl);
    sw.appendChild(cv);sw.appendChild(sbar);

    var aux=el("div","va-mat");aux.id="va-aux";

    var bar=el("div");bar.id="va-bar";
    var st=el("div");st.id="va-status";
    var ip=el("div");ip.id="va-input";
    var ta=document.createElement("textarea");
    ta.id="va-field";ta.rows=1;ta.placeholder="Message";
    ta.setAttribute("enterkeyhint","send");
    var snd=el("button",null,"\u2191");snd.id="va-send";snd.type="button";
    snd.disabled=true;snd.setAttribute("aria-label","Senden");
    ip.appendChild(ta);ip.appendChild(snd);
    bar.appendChild(st);bar.appendChild(ip);

    ta.addEventListener("input",function(){
      ta.style.height="auto";
      ta.style.height=Math.min(110,ta.scrollHeight)+"px";
      snd.disabled=!ta.value.trim();
    });
    ta.addEventListener("keydown",function(e){
      if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();snd.click();}
    });

    root.appendChild(rail);root.appendChild(side);
    root.appendChild(sw);root.appendChild(aux);root.appendChild(bar);
    return root;
  }

  function mount(){
    if(ROOT)return ROOT;
    load();
    ROOT=build();
    document.body.appendChild(ROOT);
    if(S.sideCollapsed)ROOT.classList.add("side-collapsed");
    renderStack();layout();
    if(window.ResizeObserver){RO=new ResizeObserver(layout);RO.observe(ROOT);}
    window.addEventListener("resize",layout);
    window.addEventListener("orientationchange",function(){setTimeout(layout,250);});
    if(window.visualViewport){
      window.visualViewport.addEventListener("resize",layout);
      window.visualViewport.addEventListener("scroll",layout);
    }
    return ROOT;
  }
  function unmount(){
    if(!ROOT)return;
    if(RO){try{RO.disconnect();}catch(e){}RO=null;}
    window.removeEventListener("resize",layout);
    if(window.visualViewport){
      window.visualViewport.removeEventListener("resize",layout);
      window.visualViewport.removeEventListener("scroll",layout);
    }
    ROOT.remove();ROOT=null;
  }

  window.ViewApple={
    mount:mount,unmount:unmount,refit:fit,
    body:function(id){return document.getElementById("vabody-"+id);},
    setRoomSize:function(w,h){
      var cv=document.getElementById("va-stage");
      if(!cv)return;
      cv.dataset.rw=String(w||900);cv.dataset.rh=String(h||560);
      cv.width=w||900;cv.height=h||560;fit();
    },
    setRoomTitle:function(t){
      var e=document.getElementById("va-roomtitle");
      if(e)e.textContent=t||"";
    },
    status:function(list){
      var e=document.getElementById("va-status");
      if(!e)return;
      e.innerHTML="";
      (list||[]).forEach(function(x){
        var c=document.createElement("span");
        c.className="chip";c.textContent=x;e.appendChild(c);
      });
    },
    isMounted:function(){return !!ROOT;}
  };
})();
