// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="index.html">Overview</a></li><li class="chapter-item expanded affix "><li class="part-title">Getting Started</li><li class="chapter-item expanded "><a href="getting_started/introduction.html"><strong aria-hidden="true">1.</strong> Introduction</a></li><li class="chapter-item expanded "><a href="getting_started/quick_start.html"><strong aria-hidden="true">2.</strong> Quick Start</a></li><li class="chapter-item expanded "><a href="getting_started/examples.html"><strong aria-hidden="true">3.</strong> Examples</a></li><li class="chapter-item expanded affix "><li class="part-title">User Guide</li><li class="chapter-item expanded "><a href="user_guide/api.html"><strong aria-hidden="true">4.</strong> Unified Recursion API</a></li><li class="chapter-item expanded "><a href="user_guide/aggregation.html"><strong aria-hidden="true">5.</strong> Aggregation</a></li><li class="chapter-item expanded "><a href="user_guide/configuration.html"><strong aria-hidden="true">6.</strong> Configuration</a></li><li class="chapter-item expanded "><a href="user_guide/public_inputs.html"><strong aria-hidden="true">7.</strong> Public Inputs</a></li><li class="chapter-item expanded "><a href="user_guide/integration.html"><strong aria-hidden="true">8.</strong> Integration Guide</a></li><li class="chapter-item expanded "><a href="user_guide/low_level_api.html"><strong aria-hidden="true">9.</strong> Low-Level API</a></li><li class="chapter-item expanded affix "><li class="part-title">Architecture &amp; Internals</li><li class="chapter-item expanded "><a href="architecture_and_internals/construction.html"><strong aria-hidden="true">10.</strong> Construction</a></li><li class="chapter-item expanded "><a href="architecture_and_internals/circuit_building.html"><strong aria-hidden="true">11.</strong> Circuit Building</a></li><li class="chapter-item expanded "><a href="architecture_and_internals/hashing.html"><strong aria-hidden="true">12.</strong> Hashing and Fiat-Shamir</a></li><li class="chapter-item expanded affix "><li class="part-title">Advanced Topics</li><li class="chapter-item expanded "><a href="advanced_topics/scaling.html"><strong aria-hidden="true">13.</strong> Scaling Strategies</a></li><li class="chapter-item expanded "><a href="advanced_topics/soundness.html"><strong aria-hidden="true">14.</strong> Soundness and Security</a></li><li class="chapter-item expanded "><a href="advanced_topics/debugging.html"><strong aria-hidden="true">15.</strong> Debugging</a></li><li class="chapter-item expanded affix "><li class="part-title">Appendix</li><li class="chapter-item expanded "><a href="appendix/benchmark.html"><strong aria-hidden="true">16.</strong> Benchmarks</a></li><li class="chapter-item expanded "><a href="appendix/roadmap.html"><strong aria-hidden="true">17.</strong> Roadmap</a></li><li class="chapter-item expanded "><a href="appendix/glossary.html"><strong aria-hidden="true">18.</strong> Glossary</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
