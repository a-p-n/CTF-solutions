<template>
	<v-alert
      border="top"
      type="error"
      variant="outlined"
      prominent
      v-if="show"
    >Authentication failed</v-alert>
	<form @submit="onSubmit">
	<v-text-field v-model="mission" disabled></v-text-field>
	<v-text-field v-model="secret"></v-text-field>
	<v-btn type="submit">Authorize</v-btn>
	</form>
</template>

<script>
import axios from "axios";
import { useRoute } from 'vue-router';
export default {
  data() {
  	const route = useRoute()
    return {
      mission: route.query.mission,
      secret: "",
      show: false
    };
  },
  methods: {
    onSubmit(event) {
      event.preventDefault();

      // Submit the form data to your server.
      localStorage.setItem("secret", this.secret);
      axios.post("/api/authenticate", {
        mission: this.mission,
        secret: this.secret
      }, {
			withCredentials:true
		}).then(() => {
        // Handle the successful form submission.
        this.$router.push('/Mission');
      }).catch(() => {
      	this.show = true;
        // Handle the failed form submission.
      });
    },
  },
};

</script>
