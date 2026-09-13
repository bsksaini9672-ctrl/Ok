export default {
  async fetch(request) {
    return new Response("ReplyMate License Server OK", {
      headers: { "Content-Type": "text/plain" }
    });
  }
};
