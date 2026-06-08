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

function syncModelDatalist(form) {
  const provider = form.querySelector('select[name="provider"]')?.value;
  const model = form.querySelector('input[name="model"]');
  if (!provider || !model) return;
  const list = document.getElementById('models-' + provider);
  if (list) {
    model.setAttribute('list', list.id);
  } else {
    model.removeAttribute('list');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.provider-form').forEach((form) => {
    syncProviderSections(form);
    form.querySelector('select[name="provider"]')?.addEventListener('change', () => {
      syncProviderSections(form);
    });
  });

  document.querySelectorAll('.ai-provider-form').forEach((form) => {
    syncModelDatalist(form);
    form.querySelector('select[name="provider"]')?.addEventListener('change', () => {
      syncModelDatalist(form);
    });
  });
});
