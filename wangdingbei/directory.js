document.addEventListener("DOMContentLoaded", function() {
    // 生成目录列表
    var outline = document.createElement("ul");
    outline.setAttribute("id", "outline-list");
    outline.style.cssText = "border: 1px solid #ccc;";
    document.body.insertBefore(outline, document.body.childNodes[0]);
    // 获取所有标题
    var headers = document.querySelectorAll('h1,h2,h3,h4,h5,h6');
    for (var i = 0; i < headers.length; i++) {
        var header = headers[i];
        var hash = _hashCode(header.textContent);
        // MarkdownPad2无法为中文header正确生成id，这里生成一个
        header.setAttribute("id", header.tagName + hash);
        // 找出它是H几，为后面前置空格准备
        var prefix = parseInt(header.tagName.replace('H', ''), 10);
        outline.appendChild(document.createElement("li"));
        var a = document.createElement("a");
        // 为目录项设置链接
        a.setAttribute("href", "#" + header.tagName + hash)
        // 目录项文本前面放置对应的空格
        a.innerHTML = new Array(prefix * 4).join('&nbsp;') + header.textContent;
        outline.lastChild.appendChild(a);
    }

});

// 类似Java的hash生成方式，为一段文字生成一段基本不会重复的数字
function _hashCode(txt) {
     var hash = 0;
     if (txt.length == 0) return hash;
     for (i = 0; i < txt.length; i++) {
          char = txt.charCodeAt(i);
          hash = ((hash<<5)-hash)+char;
          hash = hash & hash; // Convert to 32bit integer
     }
     return hash;
}
