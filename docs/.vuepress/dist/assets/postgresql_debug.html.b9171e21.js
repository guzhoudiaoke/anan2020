import{c as s}from"./app.b183bda1.js";import{_ as n}from"./plugin-vue_export-helper.21dcd24c.js";const a={},e=s(`<h1 id="postgresql-debug" tabindex="-1"><a class="header-anchor" href="#postgresql-debug" aria-hidden="true">#</a> PostgreSQL debug</h1><div class="language-bash ext-sh line-numbers-mode"><pre class="language-bash"><code>
<span class="token function">tar</span> xvf postgresql-14.2.tar.gz
<span class="token builtin class-name">cd</span> postgresql-14.2

./configure --enable-debug --enable-cassert <span class="token assign-left variable">CFLAGS</span><span class="token operator">=</span><span class="token string">&quot;-ggdb -Og -g3 -fno-omit-frame-pointer&quot;</span> --prefix<span class="token operator">=</span>/home/liuruyi/postgreSQL
bear -- <span class="token function">make</span>
<span class="token function">sudo</span> <span class="token function">make</span> <span class="token function">install</span>

initdb -D ~/postgreSQL/data
pg_ctl -D /home/liuruyi/postgreSQL/data -l logfile start
createdb <span class="token builtin class-name">test</span>
psql <span class="token builtin class-name">test</span>

<span class="token function">ps</span> -ef <span class="token operator">|</span> <span class="token function">grep</span> post
<span class="token function">sudo</span> gdb -p <span class="token number">19480</span>

</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br></div></div>`,2);function p(r,l){return e}var o=n(a,[["render",p]]);export{o as default};
