/* SPDX-License-Identifier: AGPL-3.0-or-later */

(() => {
  "use strict";

  const root = document.querySelector("[data-walkthrough]");
  if (!root) return;

  const slides = Array.from(root.querySelectorAll("[data-slide]"));
  const controls = root.querySelector("[data-walk-controls]");
  const toggle = root.querySelector("[data-walk-toggle]");
  const previous = root.querySelector("[data-walk-prev]");
  const next = root.querySelector("[data-walk-next]");
  const progress = root.querySelector("[data-walk-progress]");
  const time = root.querySelector("[data-walk-time]");
  const live = root.querySelector("[data-walk-live]");
  const chapterButtons = Array.from(root.querySelectorAll("[data-walk-chapter]"));
  const totalMs = Number(root.dataset.durationMs || 75000);
  const chapterMs = totalMs / slides.length;

  if (!slides.length || !controls || !toggle || !previous || !next || !progress || !time || !live) return;

  let activeIndex = 0;
  let elapsedMs = 0;
  let startedAt = 0;
  let timer = null;

  const formatTime = (milliseconds) => {
    const seconds = Math.floor(milliseconds / 1000);
    return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  };

  const updateProgress = () => {
    progress.value = Math.floor(elapsedMs / 1000);
    progress.textContent = `${progress.value} of ${progress.max} seconds`;
    time.textContent = `${formatTime(elapsedMs)} / ${formatTime(totalMs)}`;
  };

  const showChapter = (index, announce = true) => {
    activeIndex = Math.max(0, Math.min(slides.length - 1, index));
    slides.forEach((slide, slideIndex) => {
      slide.hidden = slideIndex !== activeIndex;
    });
    chapterButtons.forEach((button, buttonIndex) => {
      if (buttonIndex === activeIndex) button.setAttribute("aria-current", "step");
      else button.removeAttribute("aria-current");
    });
    previous.disabled = activeIndex === 0;
    next.disabled = activeIndex === slides.length - 1;
    if (announce) live.textContent = `Chapter ${activeIndex + 1} of ${slides.length}: ${chapterButtons[activeIndex]?.textContent || "walkthrough"}`;
  };

  const setStoppedState = (finished = false) => {
    if (timer !== null) window.clearInterval(timer);
    timer = null;
    toggle.setAttribute("aria-pressed", "false");
    toggle.textContent = finished ? "Replay 75-second walkthrough" : elapsedMs > 0 ? "Resume walkthrough" : "Start 75-second walkthrough";
  };

  const tick = () => {
    elapsedMs = Math.min(totalMs, performance.now() - startedAt);
    const nextIndex = Math.min(slides.length - 1, Math.floor(elapsedMs / chapterMs));
    if (nextIndex !== activeIndex) showChapter(nextIndex);
    updateProgress();
    if (elapsedMs >= totalMs) setStoppedState(true);
  };

  const play = () => {
    if (elapsedMs >= totalMs) {
      elapsedMs = 0;
      showChapter(0);
      updateProgress();
    }
    startedAt = performance.now() - elapsedMs;
    timer = window.setInterval(tick, 200);
    toggle.setAttribute("aria-pressed", "true");
    toggle.textContent = "Pause walkthrough";
  };

  const pause = () => {
    if (timer !== null) {
      elapsedMs = Math.min(totalMs, performance.now() - startedAt);
      updateProgress();
    }
    setStoppedState(false);
  };

  const moveTo = (index) => {
    pause();
    elapsedMs = index * chapterMs;
    showChapter(index);
    updateProgress();
  };

  root.classList.add("walkthrough-ready");
  controls.hidden = false;
  progress.max = totalMs / 1000;
  showChapter(0, false);
  updateProgress();

  toggle.addEventListener("click", () => {
    if (timer === null) play();
    else pause();
  });
  previous.addEventListener("click", () => moveTo(activeIndex - 1));
  next.addEventListener("click", () => moveTo(activeIndex + 1));
  chapterButtons.forEach((button) => {
    button.addEventListener("click", () => moveTo(Number(button.dataset.walkChapter)));
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && timer !== null) pause();
  });
})();
