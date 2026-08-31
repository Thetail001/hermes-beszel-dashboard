(function () {
  "use strict";
  var SDK = window.__HERMES_PLUGIN_SDK__;
  var React = SDK.React;
  var h = React.createElement;
  var useRef = SDK.hooks.useRef;
  var useState = SDK.hooks.useState;
  var useEffect = SDK.hooks.useEffect;

  // beszel SPA 装在 iframe 里隔离运行（React/CSS/路由互不干扰），
  // 但尺寸适配 hermes dashboard 的内容区：保留侧边栏和顶栏，不再全屏覆盖。
  function App() {
    var wrapRef = useRef(null);
    var size = useState({ w: 0, h: 0 });
    var setSize = size[1];

    useEffect(function () {
      var el = wrapRef.current;
      if (!el) return;
      var update = function () {
        setSize({ w: el.clientWidth, h: el.clientHeight });
      };
      update();
      var ro = new ResizeObserver(update);
      ro.observe(el);
      return function () { ro.disconnect(); };
    }, []);

    return h("div", {
      ref: wrapRef,
      style: {
        width: "100%",
        height: "calc(100vh - 80px)", // hermes 顶栏 + 内边距余量
        minHeight: "480px",
        borderRadius: "8px",
        overflow: "hidden",
        border: "1px solid rgba(128,128,128,.2)",
        background: "#0f1115",
      },
    },
      h("iframe", {
        src: "/dashboard-plugins/beszel/dist/index.html",
        title: "Beszel",
        style: {
          width: "100%",
          height: "100%",
          border: "none",
          display: "block",
        },
      })
    );
  }

  window.__HERMES_PLUGINS__.register("beszel", App);
})();
