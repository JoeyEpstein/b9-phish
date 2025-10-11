function labelB9Phish() {
  const HIGH = "B9-Phish/High";
  const REVIEW = "B9-Phish/Review";
  const threads = GmailApp.search('subject:("verify" OR "urgent" OR "reset password") newer_than:7d');
  threads.forEach(t => t.addLabel(GmailApp.getUserLabelByName(REVIEW) || GmailApp.createLabel(REVIEW)));
}