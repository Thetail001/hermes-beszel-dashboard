(function () {
  "use strict";
  var SDK = window.__HERMES_PLUGIN_SDK__;
  var React = SDK.React;
  var h = React.createElement;
  var useState = SDK.hooks.useState;
  var useEffect = SDK.hooks.useEffect;

  // beszel SPA 用 iframe 隔离加载：React 版本/全局样式/路由与主应用互不干扰。
  // iframe 内跑的是补丁版 beszel 前端（见 patches/001-pb-baseurl.patch）。
  function App() {
    var loading = useState(true);
    var setLoading = loading[1];

    useEffect(function () {
      setLoading(false);
    }, []);

    return h("div", {
      style: {
        position: "fixed",
        inset: "0",
        top: "0",
        left: "0",
        right: "0",
        bottom: "0",
        display: "flex",
        flexDirection: "column",
        background: "#0f1115",
      },
    },
      loading[0] ? h("div", {
        style: {
          flex: "1", display: "flex", alignItems: "center",
          justifyContent: "center", color: "#6b7280",
          fontFamily: "monospace", fontSize: "14px",
        },
      }, "loading beszel…") : null,
      h("iframe", {
        src: "/dashboard-plugins/beszel/dist/index.html",
        title: "Beszel",
        style: {
          flex: "1",
          width: "100%",
          height: "100%",
          border: "none",
          display: loading[0] ? "none" : "block",
        },
        onLoad: function () { setLoading(false); },
      })
    );
  }

  window.__HERMES_PLUGINS__.register("beszel", App);
})();
