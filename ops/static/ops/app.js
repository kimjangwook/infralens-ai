function syncProviderSections(form) {
  const provider = form.querySelector('select[name="provider"]')?.value;
  form.querySelectorAll('[data-provider-section]').forEach((section) => {
    const active = section.dataset.providerSection === provider;
    section.hidden = !active;
    section.querySelectorAll('input, textarea, select').forEach((field) => {
      field.disabled = !active;
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.provider-form').forEach((form) => {
    syncProviderSections(form);
    form.querySelector('select[name="provider"]')?.addEventListener('change', () => {
      syncProviderSections(form);
    });
  });
});
