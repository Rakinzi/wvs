from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


# ── Signature database ───────────────────────────────────────────────────────
# Each entry: pattern matched against HTML/headers/scripts, mapped to a category and tech name.
SIGNATURES: list[dict] = [

    # ════════════════════════════════════════════════════════════════════════
    # CMS / Site Builders
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'/wp-content/|/wp-includes/|wp-json', re.I),                      "category": "cms", "name": "WordPress"},
    {"pattern": re.compile(r'rel=["\']https://api\.w\.org/', re.I),                           "category": "cms", "name": "WordPress"},
    {"pattern": re.compile(r'Joomla!|/components/com_|/administrator/index\.php', re.I),      "category": "cms", "name": "Joomla"},
    {"pattern": re.compile(r'Drupal\.settings|/sites/default/files/|drupal\.js', re.I),       "category": "cms", "name": "Drupal"},
    {"pattern": re.compile(r'shopify\.com|Shopify\.theme|cdn\.shopify\.com|myshopify\.com',   re.I), "category": "cms", "name": "Shopify"},
    {"pattern": re.compile(r'squarespace\.com|static\.squarespace|sqsp\.net|sqspcdn\.com',    re.I), "category": "cms", "name": "Squarespace"},
    {"pattern": re.compile(r'ghost\.org|content/themes/casper|ghost-theme|ghost\.io',         re.I), "category": "cms", "name": "Ghost"},
    {"pattern": re.compile(r'\.wix\.com|parastorage\.com|wixstatic\.com|wixsite\.com',        re.I), "category": "cms", "name": "Wix"},
    {"pattern": re.compile(r'webflow\.com|assets\.website-files\.com|\.webflow\.',            re.I), "category": "cms", "name": "Webflow"},
    {"pattern": re.compile(r'framer\.com|framerusercontent\.com',                             re.I), "category": "cms", "name": "Framer"},
    {"pattern": re.compile(r'notion\.so|notion-static\.com',                                  re.I), "category": "cms", "name": "Notion"},
    {"pattern": re.compile(r'contentful\.com|ctfassets\.net|contentfulassets\.com',           re.I), "category": "cms", "name": "Contentful"},
    {"pattern": re.compile(r'sanity\.io|_sanity|sanitycdn\.com',                              re.I), "category": "cms", "name": "Sanity"},
    {"pattern": re.compile(r'storyblok\.com|a\.storyblok\.com',                               re.I), "category": "cms", "name": "Storyblok"},
    {"pattern": re.compile(r'prismic\.io|prismic\.cdn',                                       re.I), "category": "cms", "name": "Prismic"},
    {"pattern": re.compile(r'strapi\.io|/api/strapi',                                         re.I), "category": "cms", "name": "Strapi"},
    {"pattern": re.compile(r'payload\.cloud|payloadcms',                                      re.I), "category": "cms", "name": "Payload CMS"},
    {"pattern": re.compile(r'directus\.io|directus-',                                         re.I), "category": "cms", "name": "Directus"},
    {"pattern": re.compile(r'typo3\.|typo3cms',                                               re.I), "category": "cms", "name": "TYPO3"},
    {"pattern": re.compile(r'craft\.cms|craftcms',                                            re.I), "category": "cms", "name": "Craft CMS"},
    {"pattern": re.compile(r'concrete5|concrete/|concretecms',                                re.I), "category": "cms", "name": "Concrete CMS"},
    {"pattern": re.compile(r'umbraco\.|/umbraco/',                                            re.I), "category": "cms", "name": "Umbraco"},
    {"pattern": re.compile(r'kentico\.|/kentico/',                                             re.I), "category": "cms", "name": "Kentico"},
    {"pattern": re.compile(r'hubspot\.com|hubspot-messages-iframe|_hsp',                      re.I), "category": "cms", "name": "HubSpot CMS"},
    {"pattern": re.compile(r'sites\.google\.com|google\.com/sites',                           re.I), "category": "cms", "name": "Google Sites"},
    {"pattern": re.compile(r'cargo\.site|cargocollective\.com',                               re.I), "category": "cms", "name": "Cargo"},
    {"pattern": re.compile(r'sitecore\.|sitecore-jss',                                        re.I), "category": "cms", "name": "Sitecore"},
    {"pattern": re.compile(r'adobe\.experience|aem-cms|adobelaunch',                         re.I), "category": "cms", "name": "Adobe Experience Manager"},
    {"pattern": re.compile(r'sitefinity\.|sitefinity-',                                       re.I), "category": "cms", "name": "Sitefinity"},
    {"pattern": re.compile(r'episerver\.|optimizely\.com/cms',                                re.I), "category": "cms", "name": "Optimizely CMS"},

    # ════════════════════════════════════════════════════════════════════════
    # Hosting / PaaS / Cloud
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'vercel\.com|\.vercel\.app|x-vercel-id|x-vercel-cache',           re.I), "category": "paas", "name": "Vercel"},
    {"pattern": re.compile(r'netlify\.com|netlify\.app|x-nf-request-id',                      re.I), "category": "paas", "name": "Netlify"},
    {"pattern": re.compile(r'render\.com|onrender\.com|x-render-origin-server',               re.I), "category": "paas", "name": "Render"},
    {"pattern": re.compile(r'fly\.io|fly\.dev',                                               re.I), "category": "paas", "name": "Fly.io"},
    {"pattern": re.compile(r'railway\.app',                                                   re.I), "category": "paas", "name": "Railway"},
    {"pattern": re.compile(r'heroku\.com|herokuapp\.com|x-heroku-',                           re.I), "category": "paas", "name": "Heroku"},
    {"pattern": re.compile(r'cloudfront\.net|x-amz-cf-id',                                   re.I), "category": "paas", "name": "AWS CloudFront"},
    {"pattern": re.compile(r'\.amazonaws\.com|aws-load-balancer|x-amz-request-id',            re.I), "category": "paas", "name": "Amazon Web Services"},
    {"pattern": re.compile(r'storage\.googleapis\.com|appspot\.com|x-goog-',                  re.I), "category": "paas", "name": "Google Cloud"},
    {"pattern": re.compile(r'azurewebsites\.net|\.azure\.com|x-ms-request-id|x-azure-ref',   re.I), "category": "paas", "name": "Microsoft Azure"},
    {"pattern": re.compile(r'github\.io|githubusercontent\.com',                              re.I), "category": "paas", "name": "GitHub Pages"},
    {"pattern": re.compile(r'gitlab\.io|pages\.gitlab\.io',                                   re.I), "category": "paas", "name": "GitLab Pages"},
    {"pattern": re.compile(r'cloudflare\.com|\.cf\.pages\.dev|cloudflare pages',              re.I), "category": "paas", "name": "Cloudflare Pages"},
    {"pattern": re.compile(r'digitalocean\.com|digitaloceanspaces\.com',                      re.I), "category": "paas", "name": "DigitalOcean"},
    {"pattern": re.compile(r'linode\.com|linode\.io',                                         re.I), "category": "paas", "name": "Linode"},
    {"pattern": re.compile(r'deno\.dev|deno\.land',                                           re.I), "category": "paas", "name": "Deno Deploy"},
    {"pattern": re.compile(r'workers\.dev|\.workers\.dev',                                    re.I), "category": "paas", "name": "Cloudflare Workers"},
    {"pattern": re.compile(r'supabase\.co|supabase\.com',                                     re.I), "category": "paas", "name": "Supabase"},
    {"pattern": re.compile(r'firebase\.google\.com|firebaseapp\.com|firebasestorage',         re.I), "category": "paas", "name": "Firebase"},
    {"pattern": re.compile(r'planetscale\.com',                                               re.I), "category": "paas", "name": "PlanetScale"},
    {"pattern": re.compile(r'neon\.tech|neondb\.',                                            re.I), "category": "paas", "name": "Neon"},
    {"pattern": re.compile(r'upstash\.io|upstash\.com',                                       re.I), "category": "paas", "name": "Upstash"},

    # ════════════════════════════════════════════════════════════════════════
    # JavaScript Frameworks
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'react(?:[-.](?:dom|router))?(?:\.min)?\.js|__REACT_DEVTOOLS|data-reactroot|data-reactid', re.I), "category": "javascript-frameworks", "name": "React"},
    {"pattern": re.compile(r'_next/static|__NEXT_DATA__|__nextjs_|next-route-announcer|__NEXT_ROUTER_BASEPATH__|nextjs\.org', re.I), "category": "javascript-frameworks", "name": "Next.js"},
    {"pattern": re.compile(r'__NUXT__|_nuxt/|nuxt-link|nuxtjs\.org|nuxt\.com',               re.I), "category": "javascript-frameworks", "name": "Nuxt.js"},
    {"pattern": re.compile(r'vue(?:\.min|\.runtime)?\.js|vue@\d|v-bind:|v-on:|createApp\(|__VUE__|vuejs\.org', re.I), "category": "javascript-frameworks", "name": "Vue.js"},
    {"pattern": re.compile(r'ng-version=|angular(?:\.min)?\.js|@angular/core|platformBrowserDynamic|\[ngIf\]', re.I), "category": "javascript-frameworks", "name": "Angular"},
    {"pattern": re.compile(r'__svelte|svelte/internal|\.svelte-|svelte\.dev',                 re.I), "category": "javascript-frameworks", "name": "Svelte"},
    {"pattern": re.compile(r'__sveltekit|sveltekit|_app/immutable',                           re.I), "category": "javascript-frameworks", "name": "SvelteKit"},
    {"pattern": re.compile(r'__remixContext|remix\.run|_data\.json\?_data=root',              re.I), "category": "javascript-frameworks", "name": "Remix"},
    {"pattern": re.compile(r'___gatsby|gatsby-chunk-mapping|gatsby-image-wrapper|gatsby\.com', re.I), "category": "javascript-frameworks", "name": "Gatsby"},
    {"pattern": re.compile(r'astro-island|astro:page-load|@astrojs|astro\.build',             re.I), "category": "javascript-frameworks", "name": "Astro"},
    {"pattern": re.compile(r'solid-js|createSignal|SolidJS|solidjs\.com',                     re.I), "category": "javascript-frameworks", "name": "SolidJS"},
    {"pattern": re.compile(r'qwik|qwikcity|builder\.io/qwik',                                 re.I), "category": "javascript-frameworks", "name": "Qwik"},
    {"pattern": re.compile(r'preact(?:\.min)?\.js|preactjs\.com',                             re.I), "category": "javascript-frameworks", "name": "Preact"},
    {"pattern": re.compile(r'ember(?:\.min)?\.js|Ember\.Application|emberjs\.com',            re.I), "category": "javascript-frameworks", "name": "Ember.js"},
    {"pattern": re.compile(r'backbone(?:\.min)?\.js|Backbone\.Model',                         re.I), "category": "javascript-frameworks", "name": "Backbone.js"},
    {"pattern": re.compile(r'knockout(?:\.min)?\.js|ko\.observable\(',                        re.I), "category": "javascript-frameworks", "name": "Knockout.js"},
    {"pattern": re.compile(r'mithril(?:\.min)?\.js|m\.mount\(',                               re.I), "category": "javascript-frameworks", "name": "Mithril.js"},
    {"pattern": re.compile(r'htmx\.org|hx-get=|hx-post=|hx-swap=',                          re.I), "category": "javascript-frameworks", "name": "HTMX"},
    {"pattern": re.compile(r'alpinejs|x-data=|x-bind:|x-on:|alpine\.js',                     re.I), "category": "javascript-frameworks", "name": "Alpine.js"},
    {"pattern": re.compile(r'stimulus\.js|data-controller=|@hotwired/stimulus',               re.I), "category": "javascript-frameworks", "name": "Stimulus"},
    {"pattern": re.compile(r'turbo-frame|@hotwired/turbo|turbolinks',                         re.I), "category": "javascript-frameworks", "name": "Turbo / Hotwire"},
    {"pattern": re.compile(r'inertiajs|@inertiajs',                                           re.I), "category": "javascript-frameworks", "name": "Inertia.js"},
    {"pattern": re.compile(r'livewire\.js|wire:model=|livewire/livewire\.js',                 re.I), "category": "javascript-frameworks", "name": "Livewire"},

    # ════════════════════════════════════════════════════════════════════════
    # JavaScript Libraries
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'jquery[.-]\d[\d.]+(?:\.min)?\.js|jQuery\.fn\.jquery|jQuery v\d', re.I), "category": "javascript-libraries", "name": "jQuery"},
    {"pattern": re.compile(r'jquery-migrate',                                                 re.I), "category": "javascript-libraries", "name": "jQuery Migrate"},
    {"pattern": re.compile(r'jquery-ui',                                                      re.I), "category": "javascript-libraries", "name": "jQuery UI"},
    {"pattern": re.compile(r'moment(?:\.min)?\.js|moment\.version|moment-timezone',           re.I), "category": "javascript-libraries", "name": "Moment.js"},
    {"pattern": re.compile(r'dayjs(?:\.min)?\.js|dayjs/|day\.js',                            re.I), "category": "javascript-libraries", "name": "Day.js"},
    {"pattern": re.compile(r'date-fns|date_fns',                                              re.I), "category": "javascript-libraries", "name": "date-fns"},
    {"pattern": re.compile(r'lodash(?:\.min)?\.js|_\.VERSION|lodash/',                        re.I), "category": "javascript-libraries", "name": "Lodash"},
    {"pattern": re.compile(r'underscore(?:\.min)?\.js|_\.each\(',                             re.I), "category": "javascript-libraries", "name": "Underscore.js"},
    {"pattern": re.compile(r'ramda(?:\.min)?\.js|R\.compose\(',                               re.I), "category": "javascript-libraries", "name": "Ramda"},
    {"pattern": re.compile(r'axios(?:\.min)?\.js|axios/lib|axios\.get\(',                     re.I), "category": "javascript-libraries", "name": "Axios"},
    {"pattern": re.compile(r'superagent(?:\.min)?\.js',                                       re.I), "category": "javascript-libraries", "name": "SuperAgent"},
    {"pattern": re.compile(r'gsap(?:\.min)?\.js|gsap\.to\(|TweenMax|TweenLite|gsap\.com',    re.I), "category": "javascript-libraries", "name": "GSAP"},
    {"pattern": re.compile(r'framer-motion|motion\.div|AnimatePresence|@motionone',           re.I), "category": "javascript-libraries", "name": "Framer Motion"},
    {"pattern": re.compile(r'anime(?:\.min)?\.js|anime\(',                                    re.I), "category": "javascript-libraries", "name": "Anime.js"},
    {"pattern": re.compile(r'velocity(?:\.min)?\.js|Velocity\(',                              re.I), "category": "javascript-libraries", "name": "Velocity.js"},
    {"pattern": re.compile(r'popmotion|stylefire',                                            re.I), "category": "javascript-libraries", "name": "Popmotion"},
    {"pattern": re.compile(r'three(?:\.min)?\.js|THREE\.WebGLRenderer|three/build|threejs\.org', re.I), "category": "javascript-libraries", "name": "Three.js"},
    {"pattern": re.compile(r'babylonjs|babylon(?:\.min)?\.js|BABYLON\.',                      re.I), "category": "javascript-libraries", "name": "Babylon.js"},
    {"pattern": re.compile(r'pixi(?:\.min)?\.js|PIXI\.Application|pixijs\.com',               re.I), "category": "javascript-libraries", "name": "PixiJS"},
    {"pattern": re.compile(r'phaser(?:\.min)?\.js|Phaser\.Game\(',                            re.I), "category": "javascript-libraries", "name": "Phaser"},
    {"pattern": re.compile(r'd3(?:\.min)?\.js|d3-selection|d3\.select\(|d3js\.org',           re.I), "category": "javascript-libraries", "name": "D3.js"},
    {"pattern": re.compile(r'chart(?:\.min)?\.js|new Chart\(|chartjs\.org',                   re.I), "category": "javascript-libraries", "name": "Chart.js"},
    {"pattern": re.compile(r'echarts(?:\.min)?\.js|echarts\.apache\.org|eCharts',             re.I), "category": "javascript-libraries", "name": "Apache ECharts"},
    {"pattern": re.compile(r'highcharts(?:\.min)?\.js|Highcharts\.',                          re.I), "category": "javascript-libraries", "name": "Highcharts"},
    {"pattern": re.compile(r'apexcharts|ApexCharts',                                          re.I), "category": "javascript-libraries", "name": "ApexCharts"},
    {"pattern": re.compile(r'recharts|Recharts',                                              re.I), "category": "javascript-libraries", "name": "Recharts"},
    {"pattern": re.compile(r'swiper(?:\.min)?\.js|swiper-wrapper|new Swiper\(|swiperjs\.com', re.I), "category": "javascript-libraries", "name": "Swiper"},
    {"pattern": re.compile(r'splide(?:\.min)?\.js|Splide\(',                                  re.I), "category": "javascript-libraries", "name": "Splide"},
    {"pattern": re.compile(r'slick(?:\.min)?\.js|slick-carousel|\.slick\(',                   re.I), "category": "javascript-libraries", "name": "Slick"},
    {"pattern": re.compile(r'glide(?:\.min)?\.js|@glidejs',                                   re.I), "category": "javascript-libraries", "name": "Glide.js"},
    {"pattern": re.compile(r'aos(?:\.min)?\.js|AOS\.init\(|data-aos=',                        re.I), "category": "javascript-libraries", "name": "AOS"},
    {"pattern": re.compile(r'wow(?:\.min)?\.js|new WOW\(',                                    re.I), "category": "javascript-libraries", "name": "WOW.js"},
    {"pattern": re.compile(r'scrollreveal|ScrollReveal\(',                                    re.I), "category": "javascript-libraries", "name": "ScrollReveal"},
    {"pattern": re.compile(r'lottie(?:\.min)?\.js|lottie-web|bodymovin',                      re.I), "category": "javascript-libraries", "name": "Lottie"},
    {"pattern": re.compile(r'@tanstack/react-query|react-query|useQuery\(',                   re.I), "category": "javascript-libraries", "name": "TanStack Query"},
    {"pattern": re.compile(r'@tanstack/react-table|react-table',                              re.I), "category": "javascript-libraries", "name": "TanStack Table"},
    {"pattern": re.compile(r'zustand|create\(\(set\)',                                        re.I), "category": "javascript-libraries", "name": "Zustand"},
    {"pattern": re.compile(r'jotai|useAtom\(',                                                re.I), "category": "javascript-libraries", "name": "Jotai"},
    {"pattern": re.compile(r'recoil(?:js)?|useRecoilState\(',                                 re.I), "category": "javascript-libraries", "name": "Recoil"},
    {"pattern": re.compile(r'mobx(?:\.min)?\.js|observable\.|MobX',                           re.I), "category": "javascript-libraries", "name": "MobX"},
    {"pattern": re.compile(r'redux(?:\.min)?\.js|createStore\(|configureStore\(|@reduxjs',    re.I), "category": "javascript-libraries", "name": "Redux"},
    {"pattern": re.compile(r'xstate|createMachine\(',                                         re.I), "category": "javascript-libraries", "name": "XState"},
    {"pattern": re.compile(r'socket\.io|io\.connect\(|socket\.io\.js',                        re.I), "category": "javascript-libraries", "name": "Socket.io"},
    {"pattern": re.compile(r'@apollo/client|apollographql|ApolloClient',                      re.I), "category": "javascript-libraries", "name": "Apollo Client"},
    {"pattern": re.compile(r'urql|useQuery.*urql|@urql/core',                                 re.I), "category": "javascript-libraries", "name": "urql"},
    {"pattern": re.compile(r'swr|useSWR\(',                                                   re.I), "category": "javascript-libraries", "name": "SWR"},
    {"pattern": re.compile(r'react-hook-form|useForm\(',                                      re.I), "category": "javascript-libraries", "name": "React Hook Form"},
    {"pattern": re.compile(r'formik|useFormik\(',                                             re.I), "category": "javascript-libraries", "name": "Formik"},
    {"pattern": re.compile(r'zod(?:\.min)?\.js|z\.object\(',                                  re.I), "category": "javascript-libraries", "name": "Zod"},
    {"pattern": re.compile(r'yup(?:\.min)?\.js|yup\.object\(',                                re.I), "category": "javascript-libraries", "name": "Yup"},
    {"pattern": re.compile(r'react-router|createBrowserRouter|useNavigate\(',                 re.I), "category": "javascript-libraries", "name": "React Router"},
    {"pattern": re.compile(r'wouter|useRoute\(',                                              re.I), "category": "javascript-libraries", "name": "Wouter"},
    {"pattern": re.compile(r'react-spring|useSpring\(',                                       re.I), "category": "javascript-libraries", "name": "React Spring"},
    {"pattern": re.compile(r'react-dnd|useDrag\(|useDrop\(',                                  re.I), "category": "javascript-libraries", "name": "React DnD"},
    {"pattern": re.compile(r'dnd-kit|@dnd-kit/core',                                          re.I), "category": "javascript-libraries", "name": "dnd kit"},
    {"pattern": re.compile(r'react-beautiful-dnd|Droppable',                                  re.I), "category": "javascript-libraries", "name": "react-beautiful-dnd"},
    {"pattern": re.compile(r'react-virtualized|react-window|FixedSizeList',                   re.I), "category": "javascript-libraries", "name": "React Window"},
    {"pattern": re.compile(r'pdf-lib|pdfkit|jspdf',                                           re.I), "category": "javascript-libraries", "name": "jsPDF"},
    {"pattern": re.compile(r'html2canvas',                                                    re.I), "category": "javascript-libraries", "name": "html2canvas"},
    {"pattern": re.compile(r'marked(?:\.min)?\.js|marked\(',                                  re.I), "category": "javascript-libraries", "name": "Marked"},
    {"pattern": re.compile(r'prism(?:\.min)?\.js|Prism\.highlight|prismjs',                   re.I), "category": "javascript-libraries", "name": "Prism.js"},
    {"pattern": re.compile(r'highlight\.js|hljs\.highlight',                                  re.I), "category": "javascript-libraries", "name": "highlight.js"},
    {"pattern": re.compile(r'core-js',                                                        re.I), "category": "javascript-libraries", "name": "core-js"},
    {"pattern": re.compile(r'vite(?:\.min)?\.js|vite@\d|/@vite/client',                       re.I), "category": "javascript-libraries", "name": "Vite"},
    {"pattern": re.compile(r'webpack-runtime|__webpack_require__|webpackJsonp',               re.I), "category": "javascript-libraries", "name": "webpack"},
    {"pattern": re.compile(r'parcel-runtime|ParcelRequire',                                   re.I), "category": "javascript-libraries", "name": "Parcel"},
    {"pattern": re.compile(r'rollup(?:\.min)?\.js|rollupjs\.org',                             re.I), "category": "javascript-libraries", "name": "Rollup"},

    # ════════════════════════════════════════════════════════════════════════
    # CSS Frameworks & UI Libraries
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'bootstrap(?:\.min)?\.(?:js|css)|bootstrap@\d|btn-primary|col-md-|container-fluid', re.I), "category": "css-frameworks", "name": "Bootstrap"},
    {"pattern": re.compile(r'tailwindcss|tailwind\.config|tailwind\.min\.css|@tailwindcss',   re.I), "category": "css-frameworks", "name": "Tailwind CSS"},
    {"pattern": re.compile(r'materialize(?:\.min)?\.css|waves-effect|btn-floating',           re.I), "category": "css-frameworks", "name": "Materialize CSS"},
    {"pattern": re.compile(r'bulma(?:\.min)?\.css|is-primary.*bulma|buefy',                   re.I), "category": "css-frameworks", "name": "Bulma"},
    {"pattern": re.compile(r'foundation(?:\.min)?\.(?:css|js)|reveal-overlay|orbit-container', re.I), "category": "css-frameworks", "name": "Foundation"},
    {"pattern": re.compile(r'pure(?:-min)?\.css|pure-css|purecss\.io',                        re.I), "category": "css-frameworks", "name": "Pure CSS"},
    {"pattern": re.compile(r'skeleton(?:\.min)?\.css|getskeleton\.com',                        re.I), "category": "css-frameworks", "name": "Skeleton"},
    {"pattern": re.compile(r'milligram(?:\.min)?\.css',                                       re.I), "category": "css-frameworks", "name": "Milligram"},
    {"pattern": re.compile(r'tachyons(?:\.min)?\.css|tachyons\.io',                           re.I), "category": "css-frameworks", "name": "Tachyons"},
    {"pattern": re.compile(r'unocss|@unocss/core',                                            re.I), "category": "css-frameworks", "name": "UnoCSS"},
    {"pattern": re.compile(r'windi(?:css)?|windicss',                                         re.I), "category": "css-frameworks", "name": "Windi CSS"},
    {"pattern": re.compile(r'@mui/material|MuiButton-|MuiBox-|@material-ui',                  re.I), "category": "ui-frameworks", "name": "Material UI (MUI)"},
    {"pattern": re.compile(r'chakra-ui|@chakra-ui|ChakraProvider|chakra-',                    re.I), "category": "ui-frameworks", "name": "Chakra UI"},
    {"pattern": re.compile(r'shadcn|@radix-ui|data-radix-|cmdk',                             re.I), "category": "ui-frameworks", "name": "shadcn/ui"},
    {"pattern": re.compile(r'daisyui|daisy-|theme-controller',                                re.I), "category": "ui-frameworks", "name": "DaisyUI"},
    {"pattern": re.compile(r'mantine(?:\.min)?\.js|@mantine/core',                            re.I), "category": "ui-frameworks", "name": "Mantine"},
    {"pattern": re.compile(r'ant-design|antd|@ant-design',                                    re.I), "category": "ui-frameworks", "name": "Ant Design"},
    {"pattern": re.compile(r'next-ui|@nextui-org',                                            re.I), "category": "ui-frameworks", "name": "NextUI"},
    {"pattern": re.compile(r'headlessui|@headlessui',                                         re.I), "category": "ui-frameworks", "name": "Headless UI"},
    {"pattern": re.compile(r'ariakit|@ariakit',                                               re.I), "category": "ui-frameworks", "name": "Ariakit"},
    {"pattern": re.compile(r'prime(?:vue|react|ng)|primeflex',                                 re.I), "category": "ui-frameworks", "name": "PrimeUI"},
    {"pattern": re.compile(r'vuetify|@vuetify',                                               re.I), "category": "ui-frameworks", "name": "Vuetify"},
    {"pattern": re.compile(r'quasar(?:framework)?|@quasar',                                   re.I), "category": "ui-frameworks", "name": "Quasar"},
    {"pattern": re.compile(r'element-plus|element-ui|el-button',                              re.I), "category": "ui-frameworks", "name": "Element Plus"},
    {"pattern": re.compile(r'naive-ui|@naive-ui',                                             re.I), "category": "ui-frameworks", "name": "Naive UI"},
    {"pattern": re.compile(r'carbon-components|@carbon/react',                                re.I), "category": "ui-frameworks", "name": "IBM Carbon"},
    {"pattern": re.compile(r'spectrum-css|@adobe/spectrum',                                   re.I), "category": "ui-frameworks", "name": "Adobe Spectrum"},
    {"pattern": re.compile(r'grommet|@grommet',                                               re.I), "category": "ui-frameworks", "name": "Grommet"},
    {"pattern": re.compile(r'evergreen-ui|@evergreen-ui',                                     re.I), "category": "ui-frameworks", "name": "Evergreen"},
    {"pattern": re.compile(r'semantic-ui|fomantic-ui|ui\.semantic',                           re.I), "category": "ui-frameworks", "name": "Semantic UI"},
    {"pattern": re.compile(r'flowbite|@flowbite',                                             re.I), "category": "ui-frameworks", "name": "Flowbite"},
    {"pattern": re.compile(r'react-aria|@react-aria',                                         re.I), "category": "ui-frameworks", "name": "React Aria"},
    {"pattern": re.compile(r'ionic(?:-angular|-react|-vue)?|@ionic',                          re.I), "category": "ui-frameworks", "name": "Ionic"},
    {"pattern": re.compile(r'tremor|@tremor',                                                 re.I), "category": "ui-frameworks", "name": "Tremor"},
    {"pattern": re.compile(r'aceternity|ui\.aceternity',                                      re.I), "category": "ui-frameworks", "name": "Aceternity UI"},
    {"pattern": re.compile(r'magic-ui|magicui\.design',                                       re.I), "category": "ui-frameworks", "name": "Magic UI"},

    # ════════════════════════════════════════════════════════════════════════
    # Web Servers
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'nginx',                                                          re.I), "category": "web-servers", "name": "Nginx",        "header": "server"},
    {"pattern": re.compile(r'openresty',                                                      re.I), "category": "web-servers", "name": "OpenResty",    "header": "server"},
    {"pattern": re.compile(r'apache',                                                         re.I), "category": "web-servers", "name": "Apache",       "header": "server"},
    {"pattern": re.compile(r'microsoft-iis',                                                  re.I), "category": "web-servers", "name": "IIS",          "header": "server"},
    {"pattern": re.compile(r'lighttpd',                                                       re.I), "category": "web-servers", "name": "Lighttpd",     "header": "server"},
    {"pattern": re.compile(r'gunicorn',                                                       re.I), "category": "web-servers", "name": "Gunicorn",     "header": "server"},
    {"pattern": re.compile(r'uvicorn',                                                        re.I), "category": "web-servers", "name": "Uvicorn",      "header": "server"},
    {"pattern": re.compile(r'caddy',                                                          re.I), "category": "web-servers", "name": "Caddy",        "header": "server"},
    {"pattern": re.compile(r'traefik',                                                        re.I), "category": "web-servers", "name": "Traefik",      "header": "server"},
    {"pattern": re.compile(r'cloudflare',                                                     re.I), "category": "cdn",         "name": "Cloudflare",   "header": "server"},
    {"pattern": re.compile(r'cowboy',                                                         re.I), "category": "web-servers", "name": "Cowboy",       "header": "server"},
    {"pattern": re.compile(r'kestrel',                                                        re.I), "category": "web-servers", "name": "Kestrel",      "header": "server"},
    {"pattern": re.compile(r'tornado',                                                        re.I), "category": "web-servers", "name": "Tornado",      "header": "server"},

    # ════════════════════════════════════════════════════════════════════════
    # Programming Languages (headers + HTML signals)
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'php',                                                            re.I), "category": "programming-languages", "name": "PHP",        "header": "x-powered-by"},
    {"pattern": re.compile(r'asp\.net',                                                       re.I), "category": "programming-languages", "name": "ASP.NET",    "header": "x-powered-by"},
    {"pattern": re.compile(r'\bexpress\b',                                                    re.I), "category": "programming-languages", "name": "Node.js",    "header": "x-powered-by"},
    {"pattern": re.compile(r'next\.js',                                                       re.I), "category": "javascript-frameworks", "name": "Next.js",    "header": "x-powered-by"},
    {"pattern": re.compile(r'lua',                                                            re.I), "category": "programming-languages", "name": "Lua",         "header": "x-powered-by"},
    {"pattern": re.compile(r'ruby|thin|puma|unicorn|passenger',                               re.I), "category": "programming-languages", "name": "Ruby",        "header": "server"},
    {"pattern": re.compile(r'python|django|flask|tornado|fastapi',                            re.I), "category": "programming-languages", "name": "Python",      "header": "x-powered-by"},
    {"pattern": re.compile(r'java|tomcat|jetty|jboss|wildfly|payara',                        re.I), "category": "programming-languages", "name": "Java",        "header": "server"},
    {"pattern": re.compile(r'\.php|\.asp|\.aspx|\.jsp|\.cfm',                                re.I), "category": "programming-languages", "name": "PHP"},

    # ════════════════════════════════════════════════════════════════════════
    # Backend / API Frameworks
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'laravel|laravel_session|XSRF-TOKEN.*laravel|laravel\.com',       re.I), "category": "web-frameworks", "name": "Laravel"},
    {"pattern": re.compile(r'csrfmiddlewaretoken|django(?:rest)?|django-admin',               re.I), "category": "web-frameworks", "name": "Django"},
    {"pattern": re.compile(r'werkzeug|flask',                                                 re.I), "category": "web-frameworks", "name": "Flask"},
    {"pattern": re.compile(r'fastapi|openapi\.json.*fastapi|/docs.*swagger.*fastapi',         re.I), "category": "web-frameworks", "name": "FastAPI"},
    {"pattern": re.compile(r'starlette|starlette/',                                           re.I), "category": "web-frameworks", "name": "Starlette"},
    {"pattern": re.compile(r'rails|ruby-on-rails|/assets/application-.*\.js',                re.I), "category": "web-frameworks", "name": "Ruby on Rails"},
    {"pattern": re.compile(r'sinatra',                                                        re.I), "category": "web-frameworks", "name": "Sinatra"},
    {"pattern": re.compile(r'x-application-context|spring-security|spring-boot',             re.I), "category": "web-frameworks", "name": "Spring Boot"},
    {"pattern": re.compile(r'quarkus|smallrye',                                               re.I), "category": "web-frameworks", "name": "Quarkus"},
    {"pattern": re.compile(r'micronaut',                                                      re.I), "category": "web-frameworks", "name": "Micronaut"},
    {"pattern": re.compile(r'nestjs|@nestjs|NestFactory',                                     re.I), "category": "web-frameworks", "name": "NestJS"},
    {"pattern": re.compile(r'expressjs|express\.js|express/\d',                               re.I), "category": "web-frameworks", "name": "Express.js"},
    {"pattern": re.compile(r'fastify|@fastify',                                               re.I), "category": "web-frameworks", "name": "Fastify"},
    {"pattern": re.compile(r'hono(?:js)?|@hono',                                              re.I), "category": "web-frameworks", "name": "Hono"},
    {"pattern": re.compile(r'elysia(?:js)?|@elysiajs',                                        re.I), "category": "web-frameworks", "name": "Elysia"},
    {"pattern": re.compile(r'adonisjs|@adonisjs',                                             re.I), "category": "web-frameworks", "name": "AdonisJS"},
    {"pattern": re.compile(r'lumen|lumen/lumen',                                              re.I), "category": "web-frameworks", "name": "Lumen"},
    {"pattern": re.compile(r'symfony|sf-toolbar|sf_redirect',                                 re.I), "category": "web-frameworks", "name": "Symfony"},
    {"pattern": re.compile(r'codeigniter|ci_session',                                         re.I), "category": "web-frameworks", "name": "CodeIgniter"},
    {"pattern": re.compile(r'cakephp|cake_',                                                  re.I), "category": "web-frameworks", "name": "CakePHP"},
    {"pattern": re.compile(r'yii(?:2)?\.js|YII_CSRF_TOKEN',                                  re.I), "category": "web-frameworks", "name": "Yii"},
    {"pattern": re.compile(r'zend|laminas',                                                   re.I), "category": "web-frameworks", "name": "Laminas / Zend"},
    {"pattern": re.compile(r'gin-gonic|gin\.Context|github\.com/gin-gonic',                   re.I), "category": "web-frameworks", "name": "Gin (Go)"},
    {"pattern": re.compile(r'fiber(?:\.go)?|gofiber\.io',                                     re.I), "category": "web-frameworks", "name": "Fiber (Go)"},
    {"pattern": re.compile(r'echo\.labstack|labstack/echo',                                   re.I), "category": "web-frameworks", "name": "Echo (Go)"},
    {"pattern": re.compile(r'actix-web|actix\.rs',                                            re.I), "category": "web-frameworks", "name": "Actix (Rust)"},
    {"pattern": re.compile(r'axum|tokio-axum',                                                re.I), "category": "web-frameworks", "name": "Axum (Rust)"},
    {"pattern": re.compile(r'phoenix|\.phoenix\.|phx-',                                       re.I), "category": "web-frameworks", "name": "Phoenix (Elixir)"},
    {"pattern": re.compile(r'asp\.net.*core|microsoft\.aspnetcore',                           re.I), "category": "web-frameworks", "name": "ASP.NET Core"},

    # ════════════════════════════════════════════════════════════════════════
    # Analytics & Tag Managers
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'google-analytics\.com/analytics\.js|gtag\(|UA-\d{4,10}-\d|G-[A-Z0-9]{6,}', re.I), "category": "analytics", "name": "Google Analytics"},
    {"pattern": re.compile(r'googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+',                   re.I), "category": "tag-managers", "name": "Google Tag Manager"},
    {"pattern": re.compile(r'facebook\.net/en_US/fbevents\.js|fbq\(|_fbp=',                  re.I), "category": "analytics", "name": "Facebook Pixel"},
    {"pattern": re.compile(r'hotjar\.com|_hjSettings|hj\(',                                   re.I), "category": "analytics", "name": "Hotjar"},
    {"pattern": re.compile(r'clarity\.ms|microsoft\.clarity',                                 re.I), "category": "analytics", "name": "Microsoft Clarity"},
    {"pattern": re.compile(r'mixpanel\.com|mixpanel\.init\(',                                 re.I), "category": "analytics", "name": "Mixpanel"},
    {"pattern": re.compile(r'segment\.io|analytics\.identify\(|analytics\.track\(',           re.I), "category": "analytics", "name": "Segment"},
    {"pattern": re.compile(r'posthog\.com|posthog\.init\(|__posthog',                         re.I), "category": "analytics", "name": "PostHog"},
    {"pattern": re.compile(r'plausible\.io',                                                  re.I), "category": "analytics", "name": "Plausible"},
    {"pattern": re.compile(r'fathomhq\.com|usefathom\.com',                                   re.I), "category": "analytics", "name": "Fathom"},
    {"pattern": re.compile(r'matomo\.org|piwik\.js|_paq\.',                                   re.I), "category": "analytics", "name": "Matomo"},
    {"pattern": re.compile(r'amplitude\.com|amplitude\.getInstance',                          re.I), "category": "analytics", "name": "Amplitude"},
    {"pattern": re.compile(r'heap\.io|heap\.track\(',                                         re.I), "category": "analytics", "name": "Heap"},
    {"pattern": re.compile(r'fullstory\.com|FS\.identify\(',                                  re.I), "category": "analytics", "name": "FullStory"},
    {"pattern": re.compile(r'logrocket\.com|LogRocket\.init\(',                               re.I), "category": "analytics", "name": "LogRocket"},
    {"pattern": re.compile(r'mouseflow\.com',                                                 re.I), "category": "analytics", "name": "Mouseflow"},
    {"pattern": re.compile(r'smartlook\.com|smartlook\.init\(',                               re.I), "category": "analytics", "name": "Smartlook"},
    {"pattern": re.compile(r'kissmetrics\.com|_kq\.',                                         re.I), "category": "analytics", "name": "Kissmetrics"},
    {"pattern": re.compile(r'chartbeat\.com|_sf_async\.',                                     re.I), "category": "analytics", "name": "Chartbeat"},
    {"pattern": re.compile(r'pinterest\.com/v3/|pintrk\(',                                    re.I), "category": "analytics", "name": "Pinterest Tag"},
    {"pattern": re.compile(r'snap\.licdn\.com|linkedin\.com/px',                              re.I), "category": "analytics", "name": "LinkedIn Insight"},
    {"pattern": re.compile(r'analytics\.twitter\.com|ads\.twitter\.com|twq\(',               re.I), "category": "analytics", "name": "Twitter Pixel"},
    {"pattern": re.compile(r'tiktok\.com/i18n/pixel|analytics\.tiktok\.com',                 re.I), "category": "analytics", "name": "TikTok Pixel"},
    {"pattern": re.compile(r'sentry\.io|@sentry/browser|Sentry\.init\(',                      re.I), "category": "monitoring", "name": "Sentry"},
    {"pattern": re.compile(r'datadoghq\.com|datadog-rum|DD_RUM',                              re.I), "category": "monitoring", "name": "Datadog RUM"},
    {"pattern": re.compile(r'newrelic\.com|newrelic\.js|NREUM\.',                             re.I), "category": "monitoring", "name": "New Relic"},
    {"pattern": re.compile(r'bugsnag\.com|bugsnag\.js|Bugsnag\.start\(',                      re.I), "category": "monitoring", "name": "Bugsnag"},
    {"pattern": re.compile(r'rollbar\.com|rollbar\.js|Rollbar\.init\(',                        re.I), "category": "monitoring", "name": "Rollbar"},
    {"pattern": re.compile(r'raygun\.com|rg4js\(',                                            re.I), "category": "monitoring", "name": "Raygun"},
    {"pattern": re.compile(r'opentelemetry|@opentelemetry',                                   re.I), "category": "monitoring", "name": "OpenTelemetry"},

    # ════════════════════════════════════════════════════════════════════════
    # Live Chat & Support
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'crisp\.chat|\$crisp|CRISP_WEBSITE_ID',                           re.I), "category": "live-chat", "name": "Crisp"},
    {"pattern": re.compile(r'intercom\.com|Intercom\(|intercomSettings',                      re.I), "category": "live-chat", "name": "Intercom"},
    {"pattern": re.compile(r'tawk\.to|Tawk_API',                                              re.I), "category": "live-chat", "name": "Tawk.to"},
    {"pattern": re.compile(r'livechat\.com|LiveChatWidget\.',                                  re.I), "category": "live-chat", "name": "LiveChat"},
    {"pattern": re.compile(r'drift\.com|drift\.load\(',                                       re.I), "category": "live-chat", "name": "Drift"},
    {"pattern": re.compile(r'zendesk\.com|zopim|zE\(',                                        re.I), "category": "live-chat", "name": "Zendesk"},
    {"pattern": re.compile(r'freshchat\.com|freshdesk\.com|Freshdesk',                        re.I), "category": "live-chat", "name": "Freshchat"},
    {"pattern": re.compile(r'helpscout\.net|Beacon\.init\(',                                  re.I), "category": "live-chat", "name": "Help Scout"},
    {"pattern": re.compile(r'hubspot\.com/conversations',                                     re.I), "category": "live-chat", "name": "HubSpot Chat"},
    {"pattern": re.compile(r'chatwoot\.com|chatwoot\.init\(',                                  re.I), "category": "live-chat", "name": "Chatwoot"},
    {"pattern": re.compile(r'tidio\.com|tidioChat\.',                                          re.I), "category": "live-chat", "name": "Tidio"},

    # ════════════════════════════════════════════════════════════════════════
    # CDN
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'cloudflare-static|cf-ray|__cf_bm|cf-cache-status',               re.I), "category": "cdn", "name": "Cloudflare"},
    {"pattern": re.compile(r'cdn\.jsdelivr\.net',                                             re.I), "category": "cdn", "name": "jsDelivr"},
    {"pattern": re.compile(r'unpkg\.com',                                                     re.I), "category": "cdn", "name": "unpkg"},
    {"pattern": re.compile(r'cdnjs\.cloudflare\.com',                                         re.I), "category": "cdn", "name": "cdnjs"},
    {"pattern": re.compile(r'bunny\.net|b-cdn\.net',                                          re.I), "category": "cdn", "name": "BunnyCDN"},
    {"pattern": re.compile(r'fastly\.net|x-fastly-request-id',                                re.I), "category": "cdn", "name": "Fastly"},
    {"pattern": re.compile(r'akamaiedge\.net|akamaihd\.net',                                  re.I), "category": "cdn", "name": "Akamai"},
    {"pattern": re.compile(r'stackpathcdn\.com|maxcdn\.bootstrapcdn\.com',                    re.I), "category": "cdn", "name": "StackPath"},
    {"pattern": re.compile(r'imagekit\.io',                                                   re.I), "category": "cdn", "name": "ImageKit"},
    {"pattern": re.compile(r'imgix\.net',                                                     re.I), "category": "cdn", "name": "imgix"},
    {"pattern": re.compile(r'cloudinary\.com',                                                re.I), "category": "cdn", "name": "Cloudinary"},
    {"pattern": re.compile(r'res\.cloudinary|cloudinary\.net',                                re.I), "category": "cdn", "name": "Cloudinary"},

    # ════════════════════════════════════════════════════════════════════════
    # Auth / Identity
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'auth0\.com|auth0\.js|auth0-spa-js|cdn\.auth0\.com',              re.I), "category": "auth", "name": "Auth0"},
    {"pattern": re.compile(r'clerk\.com|clerk\.dev|__clerk|clerk-telemetry',                  re.I), "category": "auth", "name": "Clerk"},
    {"pattern": re.compile(r'supabase\.co|supabase-js|supabase\.auth',                        re.I), "category": "auth", "name": "Supabase Auth"},
    {"pattern": re.compile(r'firebase\.app|firebase/auth|firebaseapp\.com',                   re.I), "category": "auth", "name": "Firebase Auth"},
    {"pattern": re.compile(r'next-auth|nextauth\.js|/api/auth/',                              re.I), "category": "auth", "name": "NextAuth.js"},
    {"pattern": re.compile(r'kinde\.com|kinde-auth',                                         re.I), "category": "auth", "name": "Kinde"},
    {"pattern": re.compile(r'stytch\.com|stytch\.init\(',                                     re.I), "category": "auth", "name": "Stytch"},
    {"pattern": re.compile(r'okta\.com|okta-auth-js',                                        re.I), "category": "auth", "name": "Okta"},
    {"pattern": re.compile(r'onelogin\.com|onelogin-saml',                                    re.I), "category": "auth", "name": "OneLogin"},
    {"pattern": re.compile(r'keycloak|/auth/realms/',                                         re.I), "category": "auth", "name": "Keycloak"},
    {"pattern": re.compile(r'lucia-auth|lucia-session',                                       re.I), "category": "auth", "name": "Lucia Auth"},
    {"pattern": re.compile(r'better-auth|better-auth\.js',                                    re.I), "category": "auth", "name": "Better Auth"},

    # ════════════════════════════════════════════════════════════════════════
    # Payments
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'stripe\.com/v3|js\.stripe\.com|Stripe\(',                        re.I), "category": "payment-processors", "name": "Stripe"},
    {"pattern": re.compile(r'paypal\.com/sdk|paypaljs|paypal\.Buttons',                       re.I), "category": "payment-processors", "name": "PayPal"},
    {"pattern": re.compile(r'lemonsqueezy\.com|lemon\.squeezy',                               re.I), "category": "payment-processors", "name": "Lemon Squeezy"},
    {"pattern": re.compile(r'paddle\.com|Paddle\.Setup|checkout\.paddle',                     re.I), "category": "payment-processors", "name": "Paddle"},
    {"pattern": re.compile(r'square\.com|squareup\.com|web-payments-sdk',                     re.I), "category": "payment-processors", "name": "Square"},
    {"pattern": re.compile(r'braintree-web|braintree\.com',                                   re.I), "category": "payment-processors", "name": "Braintree"},
    {"pattern": re.compile(r'klarna\.com|klarna-checkout|OnSiteMessaging',                    re.I), "category": "payment-processors", "name": "Klarna"},
    {"pattern": re.compile(r'afterpay\.com|afterpay-js',                                      re.I), "category": "payment-processors", "name": "Afterpay"},
    {"pattern": re.compile(r'adyen\.com|adyen-checkout',                                      re.I), "category": "payment-processors", "name": "Adyen"},
    {"pattern": re.compile(r'razorpay\.com|Razorpay\(',                                       re.I), "category": "payment-processors", "name": "Razorpay"},

    # ════════════════════════════════════════════════════════════════════════
    # Fonts & Icon Services
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'fonts\.googleapis\.com|fonts\.gstatic\.com',                     re.I), "category": "font-services", "name": "Google Fonts"},
    {"pattern": re.compile(r'use\.typekit\.net|typekit\.com|adobe\.typekit',                  re.I), "category": "font-services", "name": "Adobe Fonts"},
    {"pattern": re.compile(r'font-awesome|fontawesome\.com|fa-solid|fa-brands|kit\.fontawesome', re.I), "category": "font-services", "name": "Font Awesome"},
    {"pattern": re.compile(r'material-symbols|material-icons',                                re.I), "category": "font-services", "name": "Material Symbols"},
    {"pattern": re.compile(r'heroicons|@heroicons',                                           re.I), "category": "font-services", "name": "Heroicons"},
    {"pattern": re.compile(r'lucide(?:-react)?|lucide\.dev',                                  re.I), "category": "font-services", "name": "Lucide Icons"},
    {"pattern": re.compile(r'phosphoricons\.com|@phosphor-icons',                             re.I), "category": "font-services", "name": "Phosphor Icons"},
    {"pattern": re.compile(r'tabler-icons|@tabler/icons',                                     re.I), "category": "font-services", "name": "Tabler Icons"},
    {"pattern": re.compile(r'feathericons|feather-icons',                                     re.I), "category": "font-services", "name": "Feather Icons"},
    {"pattern": re.compile(r'remixicon|remixdesign\.io',                                      re.I), "category": "font-services", "name": "Remix Icon"},
    {"pattern": re.compile(r'fonts\.bunny\.net',                                              re.I), "category": "font-services", "name": "Bunny Fonts"},

    # ════════════════════════════════════════════════════════════════════════
    # eCommerce
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'WooCommerce|woocommerce',                                        re.I), "category": "ecommerce", "name": "WooCommerce"},
    {"pattern": re.compile(r'Magento|/mage/adminhtml|Mage\.Cookies',                          re.I), "category": "ecommerce", "name": "Magento"},
    {"pattern": re.compile(r'bigcommerce\.com|bc_storefront',                                 re.I), "category": "ecommerce", "name": "BigCommerce"},
    {"pattern": re.compile(r'prestashop|PrestaShop',                                          re.I), "category": "ecommerce", "name": "PrestaShop"},
    {"pattern": re.compile(r'opencart|route=common/',                                         re.I), "category": "ecommerce", "name": "OpenCart"},
    {"pattern": re.compile(r'cs-cart|cscart',                                                 re.I), "category": "ecommerce", "name": "CS-Cart"},
    {"pattern": re.compile(r'medusajs|medusa-storefront',                                     re.I), "category": "ecommerce", "name": "Medusa"},
    {"pattern": re.compile(r'saleor\.io|saleor-storefront',                                   re.I), "category": "ecommerce", "name": "Saleor"},

    # ════════════════════════════════════════════════════════════════════════
    # Databases (inferred from signals in HTML / cookies)
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'/wp-content/|/wp-includes/'),                                    "category": "databases", "name": "MySQL"},
    {"pattern": re.compile(r'laravel_session|PHPSESSID',                                      re.I), "category": "databases", "name": "MySQL"},
    {"pattern": re.compile(r'mongodb|mongoose|MongoClient',                                   re.I), "category": "databases", "name": "MongoDB"},
    {"pattern": re.compile(r'postgre|psycopg|pg_pool',                                        re.I), "category": "databases", "name": "PostgreSQL"},
    {"pattern": re.compile(r'redis-server|RedisClient',                                       re.I), "category": "databases", "name": "Redis"},

    # ════════════════════════════════════════════════════════════════════════
    # Security & Compliance
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'recaptcha|google\.com/recaptcha|grecaptcha',                     re.I), "category": "security", "name": "reCAPTCHA"},
    {"pattern": re.compile(r'hcaptcha\.com|hCaptcha',                                         re.I), "category": "security", "name": "hCaptcha"},
    {"pattern": re.compile(r'turnstile\.cf|challenges\.cloudflare\.com/turnstile',            re.I), "category": "security", "name": "Cloudflare Turnstile"},
    {"pattern": re.compile(r'cookiebot\.com|Cookiebot',                                       re.I), "category": "security", "name": "Cookiebot"},
    {"pattern": re.compile(r'onetrust\.com|OneTrust',                                         re.I), "category": "security", "name": "OneTrust"},
    {"pattern": re.compile(r'cookieinformation\.com',                                         re.I), "category": "security", "name": "Cookie Information"},
    {"pattern": re.compile(r'iubenda\.com',                                                   re.I), "category": "security", "name": "iubenda"},
    {"pattern": re.compile(r'termly\.io',                                                     re.I), "category": "security", "name": "Termly"},
    {"pattern": re.compile(r'axeptio\.eu',                                                    re.I), "category": "security", "name": "Axeptio"},

    # ════════════════════════════════════════════════════════════════════════
    # Miscellaneous / SEO / Structured Data
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'application/ld\+json',                                           re.I), "category": "miscellaneous", "name": "JSON-LD"},
    {"pattern": re.compile(r'og:title|og:description|og:image',                               re.I), "category": "miscellaneous", "name": "Open Graph"},
    {"pattern": re.compile(r'<link[^>]+type=["\']application/rss\+xml',                       re.I), "category": "miscellaneous", "name": "RSS"},
    {"pattern": re.compile(r'twitter:card|twitter:title',                                     re.I), "category": "miscellaneous", "name": "Twitter Cards"},
    {"pattern": re.compile(r'<amp-|⚡|<html amp>',                                             re.I), "category": "miscellaneous", "name": "AMP"},
    {"pattern": re.compile(r'pwa|service-worker|manifest\.json.*icons',                       re.I), "category": "miscellaneous", "name": "PWA"},
    {"pattern": re.compile(r'graphql|/graphql|__schema.*types',                               re.I), "category": "miscellaneous", "name": "GraphQL"},
    {"pattern": re.compile(r'trpc\.io|@trpc/client',                                          re.I), "category": "miscellaneous", "name": "tRPC"},

    # ════════════════════════════════════════════════════════════════════════
    # WordPress inferred
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'/wp-content/|/wp-includes/'),                                    "category": "programming-languages", "name": "PHP"},

    # ════════════════════════════════════════════════════════════════════════
    # WordPress Plugins (sentinel — handled separately)
    # ════════════════════════════════════════════════════════════════════════
    {"pattern": re.compile(r'/wp-content/plugins/([^/\"\']+)',                                re.I), "category": "wordpress-plugins", "name": "__PLUGIN__"},
]

PLUGIN_RE = re.compile(r'/wp-content/plugins/([^/\"\'<>\s]+)', re.I)

RISKY_TECHS = {
    "wordpress": "Ensure WordPress core, themes, and plugins are up to date.",
    "woocommerce": "WooCommerce handles payments — ensure PCI compliance and keep plugins updated.",
    "joomla": "Ensure Joomla and all extensions are up to date.",
    "drupal": "Ensure Drupal core and modules are up to date.",
    "php": "Ensure PHP version is current and not end-of-life.",
    "jquery": "Outdated jQuery versions have known XSS vulnerabilities.",
    "bootstrap": "Older Bootstrap versions may have XSS vulnerabilities.",
    "apache": "Ensure Apache is patched and server banner is hidden.",
    "nginx": "Ensure Nginx is patched and server banner is hidden.",
    "iis": "Ensure IIS is patched and detailed error messages are disabled.",
    "stripe": "Ensure Stripe is used only over HTTPS and your CSP allows stripe.com.",
    "firebase": "Restrict Firebase security rules — open databases are a common breach vector.",
    "supabase": "Ensure Supabase Row Level Security (RLS) is enabled on all public tables.",
}

SERVER_BANNER_RE = re.compile(r"(apache|nginx|iis|openresty|lighttpd)[/\s]?([\d.]+)?", re.IGNORECASE)
WP_VERSION_RE = re.compile(r'content="WordPress (\d[\d.]+)"')
JQUERY_VERSION_RE = re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.I)
BOOTSTRAP_VERSION_RE = re.compile(r'bootstrap(?:[.-]bundle)?[.-]([\d.]+)(?:\.min)?\.(?:js|css)', re.I)

OUTDATED_VERSION_FLOORS = {
    "jQuery": (3, 5, 0),
    "Bootstrap": (5, 2, 0),
}

PACKAGE_SOURCE_PATTERNS = [
    (re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/(?P<name>[^/]+)/(?P<version>[^/]+)/', re.I), None),
    (re.compile(r'cdn\.jsdelivr\.net/npm/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)', re.I), None),
    (re.compile(r'unpkg\.com/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)', re.I), None),
    (re.compile(r'jquery[.-](?P<version>\d[\d.]+)(?:\.min)?\.js', re.I), "jquery"),
    (re.compile(r'bootstrap(?:[.-]bundle)?[.-](?P<version>\d[\d.]+)(?:\.min)?\.(?:js|css)', re.I), "bootstrap"),
    (re.compile(r'lodash(?:\.min)?[.-](?P<version>\d[\d.]+)\.js', re.I), "lodash"),
    (re.compile(r'moment(?:\.min)?[.-](?P<version>\d[\d.]+)\.js', re.I), "moment"),
    (re.compile(r'core-js[/-](?P<version>\d[\d.]+)/', re.I), "core-js"),
]

PACKAGE_NAME_MAP = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment": "moment",
    "core-js": "core-js",
}


def _fetch_with_playwright(url: str, timeout: int) -> tuple[str, dict]:
    """Returns (html, response_headers) after executing JS and following all redirects."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent="Mozilla/5.0 (compatible; WVS-TechScanner/2.0)")
        page = context.new_page()

        # Capture headers from the final settled response, not intermediate redirects
        all_responses: list = []
        page.on("response", lambda r: all_responses.append(r))

        page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        html = page.content()
        final_url = page.url

        # Pick the last response that matches the final URL
        captured_headers: dict = {}
        for r in reversed(all_responses):
            if r.url == final_url:
                try:
                    captured_headers = dict(r.headers)
                except Exception:
                    pass
                break

        browser.close()
    return html, {k.lower(): v for k, v in captured_headers.items()}


def _fetch_with_httpx(url: str, timeout: int) -> tuple[str, dict]:
    client = httpx.Client(
        timeout=timeout, follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; WVS-TechScanner/2.0)"},
    )
    resp = client.get(url)
    client.close()
    return resp.text, {k.lower(): v for k, v in resp.headers.items()}


def _fingerprint(html: str, headers: dict) -> dict[str, list[str]]:
    techs: dict[str, set] = {}
    link_header = headers.get("link", "")
    # Concatenate all header values so header-agnostic sigs can match them
    all_headers_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    html_plus_link = html + "\n" + link_header

    for sig in SIGNATURES:
        if sig["name"] == "__PLUGIN__":
            continue
        target_header = sig.get("header")
        if target_header:
            # Match against the specific header value, fall back to full header blob
            source = headers.get(target_header, "") or all_headers_blob
        else:
            source = html_plus_link
        if sig["pattern"].search(source):
            techs.setdefault(sig["category"], set()).add(sig["name"])

    # Also scan all header names+values for hosting/CDN signals not covered above
    _HEADER_HOSTING = [
        (re.compile(r'x-vercel-', re.I), "paas", "Vercel"),
        (re.compile(r'x-nf-request-id|x-netlify', re.I), "paas", "Netlify"),
        (re.compile(r'x-amz-cf-id|x-amz-request-id', re.I), "paas", "AWS CloudFront"),
        (re.compile(r'x-goog-|x-firebase-', re.I), "paas", "Google Cloud"),
        (re.compile(r'x-azure-ref|x-ms-request-id', re.I), "paas", "Azure"),
        (re.compile(r'cf-ray|__cf_bm|cf-cache-status', re.I), "cdn", "Cloudflare"),
        (re.compile(r'x-fastly-request-id', re.I), "cdn", "Fastly"),
        (re.compile(r'x-render-origin-server', re.I), "paas", "Render"),
    ]
    for pattern, category, name in _HEADER_HOSTING:
        if pattern.search(all_headers_blob):
            techs.setdefault(category, set()).add(name)

    # Deduplicate web-servers — OpenResty implies Nginx
    if "web-servers" in techs and "OpenResty" in techs["web-servers"]:
        techs["web-servers"].discard("Nginx")

    # Extract WordPress plugins
    plugins = {m.group(1) for m in PLUGIN_RE.finditer(html)}
    if plugins:
        techs["wordpress-plugins"] = plugins

    return {cat: sorted(names) for cat, names in techs.items()}


def _extract_versions(html: str) -> dict[str, str]:
    versions = {}
    m = WP_VERSION_RE.search(html)
    if m:
        versions["WordPress"] = m.group(1)
    m = JQUERY_VERSION_RE.search(html)
    if m:
        versions["jQuery"] = m.group(1)
    m = BOOTSTRAP_VERSION_RE.search(html)
    if m:
        versions["Bootstrap"] = m.group(1)
    return versions


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in re.split(r"[^\d]+", version):
        if chunk:
            parts.append(int(chunk))
    return tuple(parts)


def _version_lt(version: str, floor: tuple[int, ...]) -> bool:
    current = _version_tuple(version)
    if not current:
        return False
    normalized_current = current + (0,) * (len(floor) - len(current))
    return normalized_current[:len(floor)] < floor


def _looks_like_directory_listing(html: str) -> bool:
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    heading = " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"], limit=3))

    signals = [
        title.lower().startswith("index of /"),
        "directory listing for" in title.lower(),
        heading.lower().startswith("index of /"),
        bool(soup.find("a", href=re.compile(r"^\.\./?$"))),
        bool(soup.find(string=re.compile(r"\bParent Directory\b", re.I))),
    ]
    return sum(1 for s in signals if s) >= 2


def _extract_packages(html: str, base_url: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    discovered: dict[tuple[str, str], dict[str, str]] = {}

    candidates = []
    for tag in soup.find_all(["script", "link"]):
        raw = tag.get("src") or tag.get("href")
        if raw:
            candidates.append(urljoin(base_url, raw))

    for source in candidates:
        parsed = urlparse(source)
        candidate = source
        if parsed.query:
            candidate = candidate.replace(f"?{parsed.query}", "")

        for pattern, forced_name in PACKAGE_SOURCE_PATTERNS:
            match = pattern.search(candidate)
            if not match:
                continue
            name = forced_name or match.groupdict().get("name")
            version = match.groupdict().get("version")
            if not name or not version:
                continue
            normalized_name = PACKAGE_NAME_MAP.get(name.lower(), name.lower())
            key = (normalized_name, version)
            discovered[key] = {
                "name": normalized_name,
                "version": version,
                "ecosystem": "npm",
                "source": source,
            }
            break

    return sorted(discovered.values(), key=lambda item: (item["name"], item["version"]))


def _extract_fixed_versions(vuln: dict[str, Any]) -> list[str]:
    fixed_versions: set[str] = set()
    for affected in vuln.get("affected", []) or []:
        for entry in affected.get("ranges", []) or []:
            for event in entry.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.add(fixed)
    return sorted(fixed_versions)


def _extract_cwes(vuln: dict[str, Any]) -> list[str]:
    database_specific = vuln.get("database_specific", {}) or {}
    cwe_ids = database_specific.get("cwe_ids") or database_specific.get("cwes") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    return sorted({str(cwe).strip() for cwe in cwe_ids if str(cwe).strip()})


def _advisory_severity(vuln: dict[str, Any]) -> str:
    database_specific = vuln.get("database_specific", {}) or {}
    severity = str(database_specific.get("severity") or "").strip().title()
    if severity in {"Critical", "High", "Medium", "Low"}:
        return severity

    aliases = vuln.get("aliases", []) or []
    if any(str(alias).startswith("CVE-") for alias in aliases):
        return "High"
    return "Medium"


class TechScanner:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.advisory_client = httpx.Client(
            timeout=min(timeout, 10),
            headers={"User-Agent": "WVS-TechScanner/2.0"},
        )

    def _query_osv(self, packages: list[dict[str, str]]) -> list[dict[str, Any]]:
        advisories: list[dict[str, Any]] = []
        for package in packages[:15]:
            try:
                response = self.advisory_client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {
                            "name": package["name"],
                            "ecosystem": package["ecosystem"],
                        },
                        "version": package["version"],
                    },
                )
                response.raise_for_status()
                payload = response.json()
            except Exception:
                continue

            for vuln in payload.get("vulns", []) or []:
                aliases = vuln.get("aliases", []) or []
                cves = [alias for alias in aliases if str(alias).startswith("CVE-")]
                advisory = {
                    "package": package["name"],
                    "version": package["version"],
                    "ecosystem": package["ecosystem"],
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary") or (vuln.get("details") or "").splitlines()[0][:180],
                    "aliases": aliases,
                    "cves": cves,
                    "cwes": _extract_cwes(vuln),
                    "severity": _advisory_severity(vuln),
                    "fixed_versions": _extract_fixed_versions(vuln),
                    "references": [
                        ref.get("url")
                        for ref in (vuln.get("references", []) or [])
                        if ref.get("url")
                    ][:5],
                }
                advisories.append(advisory)
        return advisories

    def _check_server_banner(self, headers: dict) -> list[dict]:
        issues = []
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and SERVER_BANNER_RE.search(server):
            issues.append({
                "name": "Server version exposed in headers",
                "severity": "Low",
                "evidence": server,
            })
        if x_powered:
            issues.append({
                "name": "Technology stack exposed via X-Powered-By",
                "severity": "Low",
                "evidence": x_powered,
            })
        return issues

    def scan(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "ok",
            "url": url,
            "technologies": {},
            "versions": {},
            "packages": [],
            "advisories": [],
            "issues": [],
            "recommendations": [],
            "score": 100,
        }

        # Try Playwright first (handles JS challenges, SPAs, anti-bot gates)
        try:
            html, headers = _fetch_with_playwright(url, self.timeout)
        except Exception:
            try:
                html, headers = _fetch_with_httpx(url, self.timeout)
            except Exception as exc:
                return {
                    "status": "error", "url": url, "score": 0,
                    "issues": [{"name": "Tech scan failed", "evidence": str(exc), "severity": "Low"}],
                }

        result["technologies"] = _fingerprint(html, headers)
        result["versions"] = _extract_versions(html)
        result["packages"] = _extract_packages(html, url)
        result["advisories"] = self._query_osv(result["packages"])

        if _looks_like_directory_listing(html):
            result["issues"].append({
                "name": "Directory listing appears enabled",
                "severity": "Medium",
                "evidence": "The response resembles a web server directory index page.",
            })
            result["recommendations"].append("Disable autoindex / directory browsing on the web server and serve explicit index files only.")

        # Header leakage
        banner_issues = self._check_server_banner(headers)
        result["issues"].extend(banner_issues)
        if any("Server version" in i["name"] for i in banner_issues):
            result["recommendations"].append("Hide server version (ServerTokens Prod / server_tokens off).")
        if any("X-Powered-By" in i["name"] for i in banner_issues):
            result["recommendations"].append("Remove the X-Powered-By header to reduce information exposure.")

        for tech_name, version in result["versions"].items():
            floor = OUTDATED_VERSION_FLOORS.get(tech_name)
            if floor and _version_lt(version, floor):
                result["issues"].append({
                    "name": f"Outdated {tech_name} version detected",
                    "severity": "Medium",
                    "evidence": f"Detected version {version}; recommended baseline is {'.'.join(map(str, floor))} or newer.",
                })
                result["recommendations"].append(f"Upgrade {tech_name} to {'.'.join(map(str, floor))} or newer and review related client-side advisories.")

        if result["packages"]:
            result["recommendations"].extend([
                "Maintain a software bill of materials (SBOM) for exposed client-side packages.",
                "Pin dependency versions and keep lockfiles in source control.",
                "Run automated dependency scanning in CI/CD (for example OSV-Scanner, Dependabot, or Renovate).",
                "Use Subresource Integrity (SRI) or self-host critical third-party scripts loaded from CDNs.",
            ])

        for advisory in result["advisories"]:
            cve_text = ", ".join(advisory["cves"][:3]) if advisory["cves"] else advisory["id"]
            cwe_text = ", ".join(advisory["cwes"][:3]) if advisory["cwes"] else "CWE not published"
            fixed_text = (
                f" Fixed in: {', '.join(advisory['fixed_versions'][:3])}."
                if advisory["fixed_versions"] else ""
            )
            result["issues"].append({
                "name": f"Known vulnerability in {advisory['package']}@{advisory['version']}",
                "severity": advisory["severity"],
                "evidence": f"{cve_text} | {cwe_text}.{fixed_text}",
            })
            result["recommendations"].append(
                f"Upgrade {advisory['package']} from {advisory['version']} to a patched release and review the related advisory references."
            )

        # Flag risky techs
        all_techs_lower = {
            t.lower()
            for names in result["technologies"].values()
            for t in names
        }
        for risky, rec in RISKY_TECHS.items():
            if any(risky in t for t in all_techs_lower):
                result["issues"].append({
                    "name": f"Detected: {next(t for t in all_techs_lower if risky in t).title()}",
                    "severity": "Info",
                    "evidence": f"Identified in the tech stack.",
                })
                result["recommendations"].append(rec)

        non_info = [i for i in result["issues"] if i["severity"] != "Info"]
        seen_recommendations: set[str] = set()
        result["recommendations"] = [
            rec for rec in result["recommendations"]
            if not (rec in seen_recommendations or seen_recommendations.add(rec))
        ]
        result["score"] = max(0, 100 - len(non_info) * 15)
        result["status"] = "issues_found" if result["issues"] else "ok"
        return result
