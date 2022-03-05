import { defineUserConfig } from 'vuepress'
import type { DefaultThemeOptions } from 'vuepress'

export default defineUserConfig<DefaultThemeOptions>({
  // 站点配置
  lang: 'en-US',
  title: '孤舟钓客',
  description: 'Just playing around',
  base: '/',
  dest: './docs/.vuepress/dist',

  // 主题和它的配置
  theme: '@vuepress/theme-default',
  themeConfig: {
    logo: 'https://vuejs.org/images/logo.png',
    navbar: [
      { text: '简介', link: '/'},
      { text: '算法', link: '/algorithms/'},
      { text: '操作系统', link: '/os_kernel/'},
      { text: '数据库', link: '/database/'},
      { text: '编程语言', link: '/programming_language/'},
      { text: '工具', link: '/tools/'},
      { text: '安安', link: '/anan/'},
      { text: '关于', link: '/about/'},
    ],
    sidebar: {
      "/algorithms/": [
      {
        title: "算法",
        children: ["/algorithms/", "/algorithms/quicksort", "/algorithms/kth_num"],
      },
      ],
      "/os_kernel/": [
      {
        title: "操作系统",
        children: ["/os_kernel/", "/os_kernel/alloc_page", "/os_kernel/fs", "/os_kernel/linux_io"],
      },
      ],
      "/database/": [
      {
        title: "数据库",
        children: ["/database/", "/database/postgresql_debug"],
      },
      ],
      "/programming_language/": [
      {
        title: "编程语言",
        children: ["/programming_language/"],
      },
      ],
      "/tools/": [
      {
        title: "工具",
        children: ["/tools/"],
      },
      ],
      "/anan/": [
      {
        title: "安安",
        children: ["/anan/"],
      },
      ],
    }
  },
})
